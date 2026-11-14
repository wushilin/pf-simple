package io.github.wushilin.pfrelay;

import static io.github.wushilin.pfrelay.TestMain.check;
import static io.github.wushilin.pfrelay.TestMain.eq;
import static io.github.wushilin.pfrelay.TestMain.throwsA;
import static io.github.wushilin.pfrelay.TestMain.waitFor;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * The serving side's half of reusing accept legs (protocol 2,
 * docs/PROTOCOL.md §12), against a hub whose every frame the test writes.
 * Mirrors pfrelay/reuse_test.go.
 */
public final class ReuseTest {
    static final String SESSION = "0123456789abcdef0123456789abcdef";
    static final String ID1 = "1111111111111111";
    static final String ID2 = "2222222222222222";

    private ReuseTest() {}

    record AcceptReq(String id, String session, WebSocket ws) {}

    /** Answers serve and accept as a protocol 2 hub would, and hands the WebSockets to the test. */
    static final class ScriptHub implements AutoCloseable {
        final FakeHub hub;
        final BlockingQueue<WebSocket> ctl = new LinkedBlockingQueue<>();
        final BlockingQueue<AcceptReq> accepts = new LinkedBlockingQueue<>();
        final BlockingQueue<String> refusals = new LinkedBlockingQueue<>();
        volatile boolean offer = true; // offer reuse on accepts that bring the session
        // every hub-side WebSocket, held until the test ends
        final List<WebSocket> held = new CopyOnWriteArrayList<>();

        ScriptHub() throws Exception {
            hub = new FakeHub(r -> {
                switch (r.endpoint) {
                    case "serve": {
                        WebSocket ws = r.upgradeAs(2, Registration.H_SESSION, SESSION);
                        held.add(ws);
                        ctl.add(ws);
                        break;
                    }
                    case "accept": {
                        String err = r.headers.get(Client.H_ERROR);
                        if (err != null) {
                            refusals.add(r.headers.get(Client.H_CONN) + " " + err);
                            r.respond(204, null);
                            return;
                        }
                        String sess = r.headers.get(Registration.H_SESSION);
                        WebSocket ws = offer && SESSION.equals(sess)
                                ? r.upgradeAs(2, Registration.H_KEEP_ALIVE, "60") : r.upgradeAs(2);
                        held.add(ws);
                        accepts.add(new AcceptReq(r.headers.get(Client.H_CONN), sess, ws));
                        break;
                    }
                    default:
                        r.respond(404, null);
                }
            });
        }

        WebSocket nextCtl() throws InterruptedException {
            WebSocket ws = ctl.poll(10, TimeUnit.SECONDS);
            check(ws != null, "a registration");
            return ws;
        }

        AcceptReq nextAccept() throws InterruptedException {
            AcceptReq a = accepts.poll(10, TimeUnit.SECONDS);
            check(a != null, "an accept");
            return a;
        }

        Client.Builder client() throws Exception {
            return hub.client();
        }

        @Override
        public void close() throws IOException {
            for (WebSocket ws : held) {
                ws.abort();
            }
            hub.close();
        }
    }

    static void open(WebSocket ctl, String id) throws IOException {
        text(ctl, "{\"open\":\"" + id + "\"}");
    }

    static void text(WebSocket ws, String s) throws IOException {
        ws.writeFrame(WebSocket.OP_TEXT, s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Runs one connection on a leg from the hub's side, against an echo on
     * the client's: data, the hub's half-close, then the echo and the
     * client's half-close.
     */
    static void exchange(WebSocket leg) throws IOException {
        leg.writeFrame(WebSocket.OP_BINARY, "hi".getBytes(StandardCharsets.UTF_8));
        text(leg, "eof");
        StringBuilder got = new StringBuilder();
        leg.setReadTimeout(10_000);
        while (true) {
            WebSocket.Frame f = leg.readHeader();
            byte[] p = leg.readPayload(f, 1 << 20);
            if (f.op == WebSocket.OP_BINARY) {
                got.append(new String(p, StandardCharsets.UTF_8));
            } else if (f.op == WebSocket.OP_TEXT && new String(p, StandardCharsets.UTF_8).equals("eof")) {
                break;
            } else if (f.op == WebSocket.OP_CLOSE) {
                throw new EOFException("closed after " + got);
            }
        }
        eq("hi", got.toString(), "echoed");
    }

    /** The leg's next text frame; a close is answered, and is an EOFException. */
    static String expectText(WebSocket leg, int withinMs) throws IOException {
        leg.setReadTimeout(withinMs);
        while (true) {
            WebSocket.Frame f = leg.readHeader();
            byte[] p = leg.readPayload(f, 1 << 20);
            if (f.op == WebSocket.OP_TEXT) {
                return new String(p, StandardCharsets.UTF_8);
            }
            if (f.op == WebSocket.OP_CLOSE) {
                try {
                    leg.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                } catch (IOException ignored) {
                    // the client may be gone already
                }
                throw new EOFException("closed");
            }
        }
    }

    /** Records each connection's close errors, by id. */
    static final class Events implements ClientEvents {
        final Map<String, List<IOException>> closed = new ConcurrentHashMap<>();
        final List<String> opened = new CopyOnWriteArrayList<>();
        final List<String> refused = new CopyOnWriteArrayList<>();

        @Override
        public void onOpen(ConnInfo info) {
            opened.add(info.id().toString());
        }

        @Override
        public void onClose(ConnInfo info, IOException error) {
            closed.computeIfAbsent(info.id().toString(), k -> new CopyOnWriteArrayList<>()).add(error);
        }

        @Override
        public void onRefuse(ConnId id, String reason) {
            refused.add(id + " " + reason);
        }

        /** The close errors of id, once there are n of them. */
        List<IOException> closedWith(String id, int n) throws InterruptedException {
            waitFor("connection " + id + " to close " + n + " time(s)",
                    () -> closed.getOrDefault(id, List.of()).size() >= n);
            return new ArrayList<>(closed.get(id));
        }
    }

    /** Serves with listen, echoing every connection. */
    static Listener listenEcho(Client c) throws IOException {
        Listener l = c.listen();
        Thread t = new Thread(() -> {
            while (true) {
                Conn conn;
                try {
                    conn = l.accept();
                } catch (IOException e) {
                    return;
                }
                Sched.go(() -> {
                    try {
                        conn.getInputStream().transferTo(conn.getOutputStream());
                        conn.shutdownOutput();
                    } catch (IOException ignored) {
                        // the connection failed; close reports it
                    } finally {
                        conn.close();
                    }
                });
            }
        });
        t.setDaemon(true);
        t.start();
        return l;
    }

    /** A TCP echo target. */
    static ServerSocket echoTarget() throws IOException {
        ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread t = new Thread(() -> {
            while (true) {
                Socket s;
                try {
                    s = ss.accept();
                } catch (IOException e) {
                    return;
                }
                Sched.go(() -> {
                    try (s) {
                        s.getInputStream().transferTo(s.getOutputStream());
                        s.shutdownOutput();
                        s.getInputStream().read();
                    } catch (IOException ignored) {
                        // done
                    }
                });
            }
        });
        t.setDaemon(true);
        t.start();
        return ss;
    }

    static String hostPort(ServerSocket ss) {
        return "127.0.0.1:" + ss.getLocalPort();
    }

    /** Runs connection id on a fresh leg, gives the hub's idle, and checks the client keeps the leg. */
    static WebSocket keepLeg(ScriptHub h, WebSocket ctl, String id) throws Exception {
        open(ctl, id);
        AcceptReq a = h.nextAccept();
        eq(id, a.id(), "the accept's id");
        eq(SESSION, a.session(), "the accept brings the session");
        exchange(a.ws());
        text(a.ws(), "idle");
        eq("idle", expectText(a.ws(), 5000), "the client answers the hub's idle");
        return a.ws();
    }

    // ---------- the tests ----------

    public static void testOfferedHeader() {
        eq(true, Registration.offered(TestMain.hdr("X-Pf-Tunnel-Proto", "2", "X-PF-Tunnel-Keep-Alive", "60")), "60");
        eq(true, Registration.offered(TestMain.hdr("X-Pf-Tunnel-Proto", "2", "X-PF-Tunnel-Keep-Alive", "3600")), "max");
        eq(true, Registration.offered(TestMain.hdr("X-Pf-Tunnel-Proto", "2", "X-PF-Tunnel-Keep-Alive", "1")), "min");
        for (String bad : new String[] {"0", "3601", "+5", " 5", "5 ", "abc", "", "99999", "-1", "1.5"}) {
            eq(false, Registration.offered(TestMain.hdr("X-Pf-Tunnel-Proto", "2", "X-PF-Tunnel-Keep-Alive", bad)),
                    "keep-alive \"" + bad + "\"");
        }
        eq(false, Registration.offered(TestMain.hdr("X-Pf-Tunnel-Proto", "1", "X-PF-Tunnel-Keep-Alive", "60")),
                "protocol 1 answers offer nothing");
        eq(false, Registration.offered(TestMain.hdr("X-Pf-Tunnel-Proto", "2")), "no header");
    }

    public static void testProtocolOffers() throws Exception {
        String tok = "t".repeat(32);
        Client newest = Client.builder().server("https://h").word("aaaa-bbbb-cccc").serveToken(tok).build();
        eq("0-2", newest.offer(Endpoint.SERVE), "the newest");
        Client ct = Client.builder().server("https://h").word("aaaa-bbbb-cccc").clientToken("open-sesame").build();
        eq("1-2", ct.offer(Endpoint.CONNECT), "the minimum the features need");
        Client old = Client.builder().server("https://h").word("aaaa-bbbb-cccc").clientToken("open-sesame")
                .maxProto(1).build();
        eq("1-1", old.offer(Endpoint.CONNECT), "like pf-client 0.14");
        eq("0-1", old.offer(Endpoint.ACCEPT), "like pf-client 0.14");
        check(!old.reuseWanted(), "protocol 1 does not reuse");
        Client none = Client.builder().server("https://h").word("aaaa-bbbb-cccc").maxProto(-1).build();
        eq(null, none.offer(Endpoint.SERVE), "announces none");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").maxProto(3).build(), "a protocol it does not speak");
        eq(Client.DEFAULT_MAX_IDLE_LEGS, Client.builder().server("https://h").maxIdleLegs(0).build().maxIdleLegs(),
                "0 means the default");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").maxIdleLegs(-1).build(), "negative");
        eq(2, Feature.REUSE.proto(), "reuse is protocol 2");
        check(!Client.builder().server("https://h").noReuse().build().reuseWanted(), "noReuse");
        // announcing none sends neither the range nor the agent
        try (FakeHub hub = new FakeHub(r -> r.respond(204, null))) {
            hub.client().maxProto(-1).build().check();
            Map<String, String> h = hub.requests("check").get(0).headers;
            check(!h.containsKey("X-PF-Tunnel-Proto") && !h.containsKey("X-PF-Version"), "no headers: " + h);
        }
    }

    public static void testKeepsAndBindsLegs() throws Exception {
        for (boolean forward : new boolean[] {false, true}) {
            try (ScriptHub h = new ScriptHub(); ServerSocket target = echoTarget()) {
                Events ev = new Events();
                Client c = h.client().events(ev).build();
                java.io.Closeable server = forward ? c.serve(hostPort(target)) : listenEcho(c);
                try (server) {
                    WebSocket ctl = h.nextCtl();
                    WebSocket leg = keepLeg(h, ctl, ID1);
                    List<IOException> e1 = ev.closedWith(ID1, 1);
                    check(e1.size() == 1 && e1.get(0) == null, "the first connection closed with " + e1);

                    // the hub binds the idle leg: answered at once, and carried
                    text(leg, "bind " + ID2);
                    eq("bound " + ID2, expectText(leg, 5000), "bind is answered");
                    exchange(leg);
                    text(leg, "idle");
                    eq("idle", expectText(leg, 5000), "the reused leg is kept again");
                    List<IOException> e2 = ev.closedWith(ID2, 1);
                    check(e2.size() == 1 && e2.get(0) == null, "the second connection closed with " + e2);
                    eq(new Stats(2, 0, 0, 4, 4), c.stats(), (forward ? "forward" : "listen") + " stats");
                    eq(List.of(ID1, ID2), ev.opened, "each connection opened once");
                    eq(1, h.hub.requests("accept").size(), "one accept for two connections");
                }
            }
        }
    }

    public static void testVerdictTimeoutAndErr() throws Exception {
        Timing t = new Timing(1000, 30_000, 60_000, 30_000, 20_000, 60_000, 10_000, 30_000, 200);
        try (ScriptHub h = new ScriptHub()) {
            Events ev = new Events();
            try (Listener l = listenEcho(h.client().events(ev).timing(t).build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                // no verdict in time: the client closes as in protocol 1
                open(ctl, ID1);
                AcceptReq a = h.nextAccept();
                exchange(a.ws());
                long t0 = System.nanoTime();
                throwsA(EOFException.class, () -> expectText(a.ws(), 5000), "no text without a verdict");
                long took = (System.nanoTime() - t0) / 1_000_000;
                check(took < 2000, "closed after " + took + " ms, want about 200");
                eq(java.util.Arrays.asList((IOException) null), ev.closedWith(ID1, 1), "no verdict: a clean finish");

                // err: as the verdict: the connection failed
                open(ctl, ID2);
                AcceptReq b = h.nextAccept();
                exchange(b.ws());
                text(b.ws(), "err:the application side failed");
                b.ws().writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                IOException e = ev.closedWith(ID2, 1).get(0);
                check(e instanceof RemoteException
                        && ((RemoteException) e).reason().equals("the application side failed"), "closed with " + e);
            }
        }
    }

    public static void testNoOfferNoWait() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            h.offer = false;
            try (Listener l = listenEcho(h.client().build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                open(ctl, ID1);
                AcceptReq a = h.nextAccept();
                exchange(a.ws());
                long t0 = System.nanoTime();
                throwsA(EOFException.class, () -> expectText(a.ws(), 5000), "nothing but a close");
                long took = (System.nanoTime() - t0) / 1_000_000;
                check(took < 1000, "closed after " + took + " ms");
            }
        }
        // a client that does not want reuse sends no session, and is offered nothing
        try (ScriptHub h = new ScriptHub()) {
            try (Listener l = listenEcho(h.client().noReuse().build())) {
                check(l.isUp(), "up");
                open(h.nextCtl(), ID1);
                AcceptReq a = h.nextAccept();
                eq(null, a.session(), "no session without reuse");
            }
        }
    }

    public static void testIdleCapAndRegistrationLoss() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            try (Listener l = listenEcho(h.client().maxIdleLegs(1).build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                WebSocket kept = keepLeg(h, ctl, ID1);

                open(ctl, ID2);
                AcceptReq a = h.nextAccept();
                exchange(a.ws());
                text(a.ws(), "idle");
                throwsA(EOFException.class, () -> expectText(a.ws(), 5000), "a leg over the cap is closed");

                ctl.abort(); // the registration ends
                throwsA(IOException.class, () -> expectText(kept, 5000), "the idle leg goes with its registration");
            }
        }
    }

    public static void testIdleBeforeEofIsAViolation() throws Exception {
        try (ScriptHub h = new ScriptHub(); Listener l = h.client().build().listen()) {
            WebSocket ctl = h.nextCtl();
            open(ctl, ID1);
            AcceptReq a = h.nextAccept();
            Conn conn = l.accept();
            text(a.ws(), "eof");
            eq(-1, conn.getInputStream().read(), "the hub's eof");
            text(a.ws(), "idle"); // this side has not half-closed
            waitFor("the leg to close", () -> conn.error() != null);
            conn.close();
        }
    }

    public static void testReopenedIdIsANewAttempt() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            Events ev = new Events();
            try (Listener l = listenEcho(h.client().events(ev).build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                WebSocket leg = keepLeg(h, ctl, ID1);
                text(leg, "bind " + ID2);
                eq("bound " + ID2, expectText(leg, 5000), "bind is answered");
                // the hub never heard bound, and asks again
                open(ctl, ID2);
                AcceptReq a = h.nextAccept();
                eq(ID2, a.id(), "the new attempt's accept");
                exchange(a.ws());
                text(a.ws(), "idle");
                expectText(a.ws(), 5000);
                List<IOException> errs = ev.closedWith(ID2, 2);
                int dropped = 0, clean = 0;
                for (IOException e : errs) {
                    if (e instanceof DroppedException
                            && ((DroppedException) e).reason().equals(Registration.REASON_LEG_LOST)) {
                        dropped++;
                    } else if (e == null) {
                        clean++;
                    }
                }
                check(dropped == 1 && clean == 1, "closed with " + errs + "; want one abandoned attempt and one clean");
            }
        }
    }

    public static void testForwarderUnreachableAfterBound() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            ServerSocket target = echoTarget();
            Events ev = new Events();
            try (Forwarder f = h.client().events(ev).build().serve(hostPort(target))) {
                check(f.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                WebSocket leg = keepLeg(h, ctl, ID1);
                target.close(); // the target goes away
                text(leg, "bind " + ID2);
                eq("bound " + ID2, expectText(leg, 5000), "bound comes before the target is dialed");
                String v = expectText(leg, 10_000);
                check(v.startsWith("err:"), "an unreachable target after bound gave " + v);
                eq(List.of(ID2 + " " + Listener.REASON_UNREACHABLE), ev.refused, "reported as refused");
                eq(List.of(ID1), ev.opened, "a refused connection is never opened");
                check(h.refusals.isEmpty(), "not refused through accept");
            }
        }
    }

    public static void testIdleLegFrames() throws Exception {
        for (String known : new String[] {"eof", "err:x", "idle", "bound " + ID2, "bind", "bound"}) {
            check(Registration.knownLegFrame(known), "known: " + known);
        }
        for (String unknown : new String[] {"something from a later protocol", "binding", "idler", ""}) {
            check(!Registration.knownLegFrame(unknown), "unknown: " + unknown);
        }
        try (ScriptHub h = new ScriptHub()) {
            try (Listener l = listenEcho(h.client().build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                WebSocket leg = keepLeg(h, ctl, ID1);
                text(leg, "something from a later protocol"); // ignored
                text(leg, "bind " + ID2);
                eq("bound " + ID2, expectText(leg, 5000), "after unknown text, bind still works");
                exchange(leg);
                text(leg, "idle");
                eq("idle", expectText(leg, 5000), "kept again");
                text(leg, "eof"); // a stream frame on an idle leg
                throwsA(IOException.class, () -> expectText(leg, 5000), "a known frame in the wrong state closes the leg");
            }
        }
        // binary data on an idle leg closes it too
        try (ScriptHub h = new ScriptHub()) {
            try (Listener l = listenEcho(h.client().build())) {
                check(l.isUp(), "up");
                WebSocket leg = keepLeg(h, h.nextCtl(), ID1);
                leg.writeFrame(WebSocket.OP_BINARY, new byte[] {1});
                throwsA(IOException.class, () -> expectText(leg, 5000), "data on an idle leg closes it");
            }
        }
    }

    /** A kept leg gives its place back however it ends, not only when it is bound. */
    public static void testIdleLegGivesItsPlaceBack() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            try (Listener l = listenEcho(h.client().maxIdleLegs(1).build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                String[] ids = {"1111111111111111", "2222222222222222", "3333333333333333"};
                for (String id : ids) {
                    // with room for one idle leg, each is kept only if the last gave its place back
                    WebSocket leg = keepLeg(h, ctl, id);
                    leg.writeFrame(WebSocket.OP_CLOSE, new byte[0]); // the hub closes it
                    throwsA(IOException.class, () -> expectText(leg, 5000), "the leg closes");
                }
            }
        }
    }

    /**
     * A bound attempt the hub asks for again is abandoned and reported
     * failed, even when the application holding it closes it quietly; the
     * new attempt is carried.
     */
    public static void testAbandonedAttemptIsFailed() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            Events ev = new Events();
            try (Listener l = h.client().events(ev).build().listen()) {
                BlockingQueue<Conn> held = new LinkedBlockingQueue<>();
                Thread t = new Thread(() -> {
                    while (true) {
                        try {
                            held.add(l.accept());
                        } catch (IOException e) {
                            return;
                        }
                    }
                });
                t.setDaemon(true);
                t.start();
                WebSocket ctl = h.nextCtl();
                open(ctl, ID1);
                AcceptReq a = h.nextAccept();
                Conn first = held.poll(10, TimeUnit.SECONDS);
                Sched.go(() -> {
                    try {
                        first.getInputStream().transferTo(first.getOutputStream());
                        first.shutdownOutput();
                    } catch (IOException ignored) {
                        // reported by close
                    } finally {
                        first.close();
                    }
                });
                exchange(a.ws());
                text(a.ws(), "idle");
                eq("idle", expectText(a.ws(), 5000), "kept");
                text(a.ws(), "bind " + ID2);
                eq("bound " + ID2, expectText(a.ws(), 5000), "bind is answered");
                Conn old = held.poll(10, TimeUnit.SECONDS); // held, neither read nor written
                check(old != null, "the bound attempt is accepted");
                open(ctl, ID2);
                h.nextAccept();
                check(held.poll(10, TimeUnit.SECONDS) != null, "the new attempt is accepted");
                old.close(); // quietly
                IOException e = ev.closedWith(ID2, 1).get(0);
                check(e instanceof DroppedException
                        && ((DroppedException) e).reason().equals(Registration.REASON_LEG_LOST),
                        "the abandoned attempt closed with " + e);
            }
        }
    }

    /** A bind for an id that already came with an open message is refused: the leg closes, nothing opens twice. */
    public static void testLateBindIsRefused() throws Exception {
        try (ScriptHub h = new ScriptHub()) {
            Events ev = new Events();
            try (Listener l = listenEcho(h.client().events(ev).build())) {
                check(l.isUp(), "up");
                WebSocket ctl = h.nextCtl();
                WebSocket leg = keepLeg(h, ctl, ID1);
                open(ctl, ID2);
                h.nextAccept();
                Thread.sleep(50);
                text(leg, "bind " + ID2);
                throwsA(IOException.class, () -> expectText(leg, 5000), "a late bind is refused");
                eq(1L, ev.opened.stream().filter(ID2::equals).count(), "opened once");
            }
        }
    }

    /**
     * An open message for an id this registration never bound abandons
     * nothing, and abandoning only ever touches serving-side connections:
     * the same client may be connecting through its own tunnel.
     */
    public static void testAbandonSparesTheConnectingSide() throws Exception {
        try (TestMain.Pair p = new TestMain.Pair()) {
            Client c = TestMain.localClient(Timing.DEFAULT);
            Conn mine = new Conn(p.client, c, new ConnId(ID1), Side.CONNECT);
            Registration reg = new Registration(c, TestMain.hdr(), (r, id, leg) -> { });
            check(!reg.tookOpen(ID1), "an id never bound is no new attempt");
            c.abandon(ID1); // even if asked, the connecting side is left alone
            Thread.sleep(100);
            check(mine.error() == null && c.stats().active() == 1, "the connecting connection is untouched");
            check(reg.takeBind(ID2) && reg.tookOpen(ID2) && reg.abandoned(ID2), "bound, then opened: abandoned");
            check(!reg.takeBind(ID1), "a bind after an open is refused");
            mine.fail("done");
        }
    }
}
