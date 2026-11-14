package io.github.wushilin.pfrelay;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

/**
 * The SDK's tests, without a test framework: every public static void
 * method whose name starts with "test" is run, and the program exits 1 if
 * any of them throws.
 */
public final class TestMain {
    public static void main(String[] args) throws Exception {
        List<String> failed = new ArrayList<>();
        int ran = 0;
        for (Method m : TestMain.class.getDeclaredMethods()) {
            if (!m.getName().startsWith("test") || !Modifier.isStatic(m.getModifiers())) {
                continue;
            }
            if (args.length > 0 && Arrays.stream(args).noneMatch(a -> m.getName().contains(a))) {
                continue;
            }
            ran++;
            long t0 = System.nanoTime();
            try {
                m.invoke(null);
                System.out.printf("ok    %s (%d ms)%n", m.getName(), (System.nanoTime() - t0) / 1_000_000);
            } catch (java.lang.reflect.InvocationTargetException e) {
                failed.add(m.getName());
                System.out.printf("FAIL  %s: %s%n", m.getName(), e.getCause());
                e.getCause().printStackTrace(System.out);
            }
        }
        System.out.printf("%d tests, %d failed%n", ran, failed.size());
        if (!failed.isEmpty()) {
            System.out.println("failed: " + failed);
            System.exit(1);
        }
        System.exit(0);
    }

    // ---------- assertions ----------

    static void check(boolean ok, String what) {
        if (!ok) {
            throw new AssertionError(what);
        }
    }

    static void eq(Object want, Object got, String what) {
        if (!java.util.Objects.equals(want, got)) {
            throw new AssertionError(what + ": want " + want + ", got " + got);
        }
    }

    interface Body {
        void run() throws Exception;
    }

    static <T extends Throwable> T throwsA(Class<T> type, Body b, String what) {
        try {
            b.run();
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                return type.cast(t);
            }
            throw new AssertionError(what + ": threw " + t + ", want " + type.getSimpleName(), t);
        }
        throw new AssertionError(what + ": did not throw " + type.getSimpleName());
    }

    // ---------- values ----------

    public static void testWords() {
        for (int i = 0; i < 200; i++) {
            String w = Words.newWord();
            check(w.matches("[abcdefghjkmnpqrstuvwxyz23456789]{4}-[abcdefghjkmnpqrstuvwxyz23456789]{4}-"
                    + "[abcdefghjkmnpqrstuvwxyz23456789]{4}"), "generated word " + w);
            eq(w, Words.normalize(w), "a generated word is normal");
        }
        eq("k3f9-x2mq-7hpa", Words.normalize("  K3F9-x2MQ-7hpa\n"), "normalize");
        eq("0000-oooo-1111", Words.normalize("0000-OOOO-1111"), "typed words may use any letter or digit");
        for (String bad : new String[] {"", "k3f9x2mq7hpa", "k3f9-x2mq-7hp", "k3f9-x2mq-7hpa-", "k3f9_x2mq_7hpa",
                "k3f9-x2mq-7hpä"}) {
            throwsA(IllegalArgumentException.class, () -> Words.normalize(bad), "word " + bad);
        }
    }

    public static void testBaseURL() {
        eq("https://hub.example", Client.normalizeBase("https://hub.example"), "bare");
        eq("https://hub.example:8443", Client.normalizeBase(" https://HUB.example:8443/ "), "slash");
        eq("https://hub.example", Client.normalizeBase("https://hub.example/pf"), "/pf");
        eq("https://hub.example", Client.normalizeBase("https://hub.example/pf/"), "/pf/");
        eq("https://[::1]:9", Client.normalizeBase("https://[::1]:9/"), "ipv6");
        for (String bad : new String[] {"http://hub.example", "hub.example", "https://hub.example/x",
                "https://hub.example/pf/api", "https://", "https://hub.example/?a=b"}) {
            throwsA(IllegalArgumentException.class, () -> Client.normalizeBase(bad), "url " + bad);
        }
    }

    public static void testBuilderValidation() {
        String good = "a".repeat(32);
        Client.builder().server("https://h").word("aaaa-bbbb-cccc").serveToken(good).clientToken("12345678")
                .name("x").build();
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").serveToken("short").build(), "short serve token");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").serveToken("a".repeat(129)).build(), "long serve token");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").serveToken("a".repeat(31) + " ").build(), "space");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").clientToken("1234567").build(), "short client token");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").clientToken("1234567é").build(), "non-ASCII token");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").name("   ").build(), "empty name");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").name("a".repeat(65)).build(), "long name");
        throwsA(IllegalArgumentException.class,
                () -> Client.builder().server("https://h").name("a\tb").build(), "control in name");
        Client.builder().server("https://h").name("é".repeat(64)).build(); // characters, not bytes
        throwsA(IllegalArgumentException.class, () -> Client.builder().word("aaaa-bbbb-cccc").build(), "no server");
        throwsA(IllegalStateException.class,
                () -> Client.builder().server("https://h").serveToken(good).build().listen(), "listen without a name");
        throwsA(IllegalStateException.class, () -> Client.builder().server("https://h").build().dial(), "no word");
    }

    public static void testClientTokenHash() {
        eq("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Client.sha256Hex(""), "sha256");
        Client c = Client.builder().server("https://h").word("aaaa-bbbb-cccc").clientToken("open-sesame")
                .name("Office SSH").target("localhost:22").build();
        Map<String, String> h = c.serveHeader();
        eq(Client.sha256Hex("open-sesame"), h.get(Client.H_CLIENT_HASH), "hash header");
        eq("Office+SSH", h.get(Client.H_NAME), "name is query-escaped");
        eq("localhost:22", h.get(Client.H_TARGET), "target");
        check(!h.containsKey(Client.H_SERVE), "no serve token, none sent");
    }

    // ---------- protocol negotiation ----------

    static Map<String, String> hdr(String... kv) {
        Map<String, String> m = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    public static void testOffer() {
        String tok = "t".repeat(32);
        Client plain = Client.builder().server("https://h").word("aaaa-bbbb-cccc").serveToken(tok).build();
        eq("0-1", plain.offer("serve"), "plain serve");
        eq("0-1", plain.offer("connect"), "plain connect");
        eq("0-1", plain.offer("accept"), "accept");
        Client anon = Client.builder().server("https://h").word("aaaa-bbbb-cccc").build();
        eq("1-1", anon.offer("serve"), "anonymous serve");
        eq("0-1", anon.offer("connect"), "connect needs no serve token");
        Client ct = Client.builder().server("https://h").word("aaaa-bbbb-cccc").serveToken(tok)
                .clientToken("open-sesame").build();
        eq("1-1", ct.offer("serve"), "serve with a client token");
        eq("1-1", ct.offer("connect"), "connect with a client token");
        eq("1-1", ct.offer("check"), "check with a client token");
        eq("0-1", ct.offer("accept"), "accept needs no client token");
        eq("0-1", ct.offer("version"), "version");
    }

    public static void testAnswered() throws Exception {
        Client ct = Client.builder().server("https://h").word("aaaa-bbbb-cccc").clientToken("open-sesame").build();
        ProtoException e = throwsA(ProtoException.class, () -> ct.answered("check", hdr()), "silent hub");
        eq(0, e.serverProto(), "server proto");
        eq(Feature.CLIENT_TOKEN, e.need(), "feature");
        check(e.getMessage().contains("too old for a client token"), e.getMessage());
        throwsA(ProtoException.class, () -> ct.answered("connect", hdr("X-PF-Tunnel-Proto", "nonsense")), "garbage");
        throwsA(ProtoException.class, () -> ct.answered("serve", hdr("x-pf-tunnel-proto", "0")), "proto 0");
        ct.answered("check", hdr("X-Pf-Tunnel-Proto", " 1 "));
        ct.answered("check", hdr("X-Pf-Tunnel-Proto", "2"));
        ct.answered("accept", hdr()); // accept depends on nothing
        Client anon = Client.builder().server("https://h").word("aaaa-bbbb-cccc").build();
        eq(Feature.ANONYMOUS_SERVE, throwsA(ProtoException.class, () -> anon.answered("serve", hdr()), "anon").need(),
                "anonymous serve feature");
        anon.answered("connect", hdr());
    }

    public static void testExplain() {
        check(Client.explain(403, "access denied", hdr()) instanceof AccessDeniedException, "403");
        eq("access denied", Client.explain(403, "", hdr()).getMessage(), "403 message");
        StatusException e = Client.explain(409, "this word is bound to another tenant", hdr());
        check(e.isFinal() && e.getMessage().contains("another tenant"), e.getMessage());
        check(Client.explain(404, "", hdr()).getMessage().contains("does not accept tunnels"), "404");
        check(!Client.explain(429, "", hdr()).isFinal(), "429 is retried");
        check(!Client.explain(408, "", hdr()).isFinal(), "408 is retried");
        check(!Client.explain(503, "", hdr()).isFinal(), "503 is retried");
        check(Client.explain(400, "", hdr()).isFinal(), "400 is final");
        check(Client.explain(426, "upgrade", hdr()).isFinal(), "426 is final");
    }

    // ---------- JSON and HTTP ----------

    public static void testJson() throws Exception {
        Map<String, Object> m = Json.parseObject(
                "{\"version\": \"0.14.0\", \"protoMin\": 0, \"protoMax\": 1, \"token\": \"al\\u0069ce\\n\","
                        + " \"extra\": [1, {\"a\": null}, true, -2.5e3]}");
        eq("0.14.0", m.get("version"), "string");
        eq(1.0, m.get("protoMax"), "number");
        eq("alice\n", m.get("token"), "escapes");
        throwsA(IOException.class, () -> Json.parse("{\"a\": 1,}"), "trailing comma");
        throwsA(IOException.class, () -> Json.parse("{\"a\": 1} x"), "trailing text");
        throwsA(IOException.class, () -> Json.parseObject("[1]"), "not an object");
        eq("\"a\\\"b\\\\c\\u0001\"", Json.quote("a\"b\\c\u0001"), "quote");
        ServerInfo info = new ServerInfo("0.14.0", 0, 1, "alice");
        Map<String, Object> back = Json.parseObject(info.toJson());
        eq("alice", back.get("token"), "round trip");
        eq("8f14e45fceea167a", Listener.openId("{\"open\":\"8f14e45fceea167a\",\"new\":1}"), "open");
        eq(null, Listener.openId("{\"open\":\"\"}"), "empty open");
        eq(null, Listener.openId("{\"close\":\"x\"}"), "no open");
        eq(null, Listener.openId("hello"), "not JSON");
        eq(null, Listener.openId("{\"open\":5}"), "not a string");
    }

    public static void testHttpParsing() throws Exception {
        String json = "{\"error\":\"bound to another tenant\"}\n";
        String raw = "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nX-Pf-Tunnel-Proto: 1\r\n"
                + "Content-Length: " + json.length() + "\r\n\r\n" + json + ".....extra";
        InputStream in = new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8));
        Http.Response r = Http.readHead(in);
        eq(409, r.status, "status");
        eq("1", r.headers.get("x-pf-tunnel-proto"), "case-insensitive headers");
        r.body = Http.readBody(in, r);
        eq(json.length(), r.body.length, "content-length body");
        eq("bound to another tenant", r.errorText(), "error text");

        raw = "HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nproxy\r\n6;x=y\r\n broke\r\n0\r\n\r\n";
        in = new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8));
        r = Http.readHead(in);
        r.body = Http.readBody(in, r);
        eq("proxy broke", r.errorText(), "chunked plain text");

        eq("", Http.errorText("<html><body>Bad gateway</body></html>".getBytes(StandardCharsets.UTF_8)), "html");
        eq("", Http.errorText(new byte[0]), "empty");
        raw = "HTTP/1.1 204 No Content\r\n\r\n";
        in = new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8));
        r = Http.readHead(in);
        eq(0, Http.readBody(in, r).length, "204 has no body");
        // RFC 6455's example
        eq("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", Http.accept("dGhlIHNhbXBsZSBub25jZQ=="), "accept key");
        eq("ab", Http.headerValue("a\r\nb"), "no header injection");
    }

    // ---------- streams, against a fake hub ----------

    /** A connected pair: the SDK's client WebSocket and a hub-side one, over loopback TCP. */
    static final class Pair implements AutoCloseable {
        final WebSocket client;
        final WebSocket hub;
        final Socket cs;
        final Socket hs;

        Pair() throws IOException {
            try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                cs = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
                hs = ss.accept();
            }
            cs.setTcpNoDelay(true);
            hs.setTcpNoDelay(true);
            client = new WebSocket(cs, cs, new java.io.BufferedInputStream(cs.getInputStream()),
                    cs.getOutputStream(), true, hdr("X-PF-Tunnel-Conn", "0123456789abcdef"));
            hub = new WebSocket(hs, hs, new java.io.BufferedInputStream(hs.getInputStream()),
                    hs.getOutputStream(), false, null);
            hs.setSoTimeout(10_000);
        }

        void hubText(String s) throws IOException {
            hub.writeFrame(WebSocket.OP_TEXT, s.getBytes(StandardCharsets.UTF_8));
        }

        /** The next frame the hub gets that is not a ping: its opcode and payload. */
        Object[] hubNext() throws IOException {
            while (true) {
                WebSocket.Frame f = hub.readHeader();
                byte[] p = hub.readPayload(f, 2 << 20);
                if (f.op != WebSocket.OP_PING) {
                    return new Object[] {f.op, p};
                }
            }
        }

        String hubNextText() throws IOException {
            Object[] f = hubNext();
            eq(WebSocket.OP_TEXT, f[0], "a text frame");
            return new String((byte[]) f[1], StandardCharsets.UTF_8);
        }

        int hubAvailable() throws IOException {
            return hs.getInputStream().available();
        }

        @Override
        public void close() throws IOException {
            cs.close();
            hs.close();
        }
    }

    static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[7777];
        int n;
        while ((n = in.read(buf)) >= 0) {
            b.write(buf, 0, n);
        }
        return b.toByteArray();
    }

    static void waitFor(String what, java.util.function.BooleanSupplier ok) throws InterruptedException {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!ok.getAsBoolean()) {
            if (System.nanoTime() > end) {
                throw new AssertionError("timed out waiting for " + what);
            }
            Thread.sleep(10);
        }
    }

    public static void testStreamEchoAndCleanClose() throws Exception {
        try (Pair p = new Pair()) {
            Registry reg = new Registry();
            Conn c = new Conn(p.client, reg, "0123456789abcdef", Side.CONNECT);
            byte[] payload = new byte[300_000];
            new Random(1).nextBytes(payload);
            OutputStream out = c.getOutputStream();
            out.write(payload);
            out.close(); // half-closes
            check(c.wroteEof(), "wrote eof");
            throwsA(IOException.class, () -> c.getOutputStream().write(1), "write after eof");
            // the hub gets the bytes in frames of at most 64 KiB, then eof
            java.io.ByteArrayOutputStream got = new java.io.ByteArrayOutputStream();
            while (true) {
                Object[] f = p.hubNext();
                if ((int) f[0] == WebSocket.OP_TEXT) {
                    eq("eof", new String((byte[]) f[1], StandardCharsets.UTF_8), "eof after the data");
                    break;
                }
                eq(WebSocket.OP_BINARY, f[0], "data frame");
                check(((byte[]) f[1]).length <= 64 << 10, "frames of at most 64 KiB");
                got.write((byte[]) f[1]);
            }
            check(Arrays.equals(payload, got.toByteArray()), "the hub got what was sent");
            // the hub sends back data, fragmented, with a pong, an unknown text and an empty frame mixed in
            p.hub.writeFrame(WebSocket.OP_BINARY, payload, 0, 1000);
            p.hub.writeFrame(WebSocket.OP_PONG, new byte[0]);
            p.hubText("hello");
            p.hub.writeFrame(WebSocket.OP_BINARY, new byte[0]);
            p.hub.writeFrame(WebSocket.OP_CONT, payload, 1000, payload.length - 1000);
            p.hub.writeFrame(WebSocket.OP_PING, new byte[0]);
            p.hubText("eof");
            byte[] back = readAll(c.getInputStream());
            check(Arrays.equals(payload, back), "the client got what the hub sent: " + back.length);
            eq(-1, c.getInputStream().read(), "still the end");
            check(c.readEof(), "read eof");
            ConnInfo info = c.info();
            eq((long) payload.length, info.sent(), "sent");
            eq((long) payload.length, info.received(), "received");
            eq(1L, reg.stats().active(), "active");
            eq(1, reg.conns().size(), "conns");
            // clean close: the client sends close and waits for the hub's
            Thread closer = new Thread(c::close);
            long t0 = System.nanoTime();
            closer.start();
            Object[] f = p.hubNext();
            eq(WebSocket.OP_CLOSE, f[0], "close frame");
            p.hub.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
            closer.join(5000);
            check(!closer.isAlive(), "close returned");
            check(System.nanoTime() - t0 < TimeUnit.SECONDS.toNanos(2), "close did not wait for the timeout");
            eq(null, c.error(), "a clean finish");
            Stats st = reg.stats();
            eq(new Stats(1, 0, 0, payload.length, payload.length), st, "stats");
            eq(0, reg.conns().size(), "no conns");
        }
    }

    public static void testErrorAfterEOF() throws Exception {
        try (Pair p = new Pair()) {
            Registry reg = new Registry();
            Conn c = new Conn(p.client, reg, "id", Side.SERVE);
            p.hub.writeFrame(WebSocket.OP_BINARY, "abc".getBytes(StandardCharsets.UTF_8));
            p.hubText("eof");
            eq("abc", new String(readAll(c.getInputStream()), StandardCharsets.UTF_8), "data then end");
            eq(null, c.error(), "fine so far");
            p.hubText("err:the target reset its connection\u0007 to pf-client serve");
            waitFor("the reason", () -> c.error() != null);
            check(c.error() instanceof RemoteException, "a remote error: " + c.error());
            eq("the target reset its connection to pf-client serve", ((RemoteException) c.error()).reason(),
                    "the reason, cleaned");
            p.hub.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
            c.close();
            eq(1L, reg.stats().failed(), "counted as failed");
        }
    }

    public static void testErrorBeforeEOF() throws Exception {
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            p.hub.writeFrame(WebSocket.OP_BINARY, "ab".getBytes(StandardCharsets.UTF_8));
            p.hubText("err:" + "x".repeat(500));
            p.hub.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
            InputStream in = c.getInputStream();
            byte[] two = new byte[2];
            eq(2, in.read(two), "the data before the failure");
            RemoteException e = throwsA(RemoteException.class, () -> in.read(), "then the reason");
            eq(200, e.reason().length(), "cut to 200");
            throwsA(RemoteException.class, () -> in.read(), "and again");
            check(c.error() instanceof RemoteException, "error()");
            c.close();
        }
    }

    public static void testCloseWithoutEOFIsBroken() throws Exception {
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            p.hub.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
            IOException e = throwsA(IOException.class, () -> c.getInputStream().read(), "a broken stream");
            check(!(e instanceof RemoteException), "not a remote reason: " + e);
            check(c.error() != null, "error()");
            eq(WebSocket.OP_CLOSE, p.hubNext()[0], "the close is answered");
            c.fail("late");
            throwsA(IOException.class, () -> p.hubNext(), "nothing follows the close");
        }
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            p.hs.close(); // TCP ends without a close frame
            throwsA(IOException.class, () -> c.getInputStream().read(), "a lost link is not an end");
        }
    }

    public static void testBadFrames() throws Exception {
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            // a masked frame from the "server": written raw
            p.hs.getOutputStream().write(new byte[] {(byte) 0x82, (byte) 0x81, 1, 2, 3, 4, 5});
            throwsA(IOException.class, () -> c.getInputStream().read(), "masked server frame");
        }
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            p.hubText("eof");
            eq(-1, c.getInputStream().read(), "eof");
            p.hub.writeFrame(WebSocket.OP_BINARY, new byte[] {1});
            waitFor("data after eof to break the stream", () -> c.error() != null);
        }
    }

    public static void testFail() throws Exception {
        try (Pair p = new Pair()) {
            Registry reg = new Registry();
            Conn c = new Conn(p.client, reg, "id", Side.SERVE);
            c.fail("the serving side could not reach its target\n");
            eq("err:the serving side could not reach its target", p.hubNextText(), "the reason");
            eq(WebSocket.OP_CLOSE, p.hubNext()[0], "then close");
            eq(new Stats(1, 0, 1, 0, 0), reg.stats(), "failed");
            throwsA(IOException.class, () -> c.getOutputStream().write(1), "closed");
            throwsA(IOException.class, () -> c.getInputStream().read(), "closed");
        }
    }

    public static void testCloseHalfClosesFirst() throws Exception {
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            c.getOutputStream().write("hi".getBytes(StandardCharsets.UTF_8));
            c.close();
            eq(WebSocket.OP_BINARY, p.hubNext()[0], "data");
            eq("eof", p.hubNextText(), "eof before the cut");
        }
    }

    public static void testReadTimeout() throws Exception {
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            c.setSoTimeout(100);
            long t0 = System.nanoTime();
            throwsA(SocketTimeoutException.class, () -> c.getInputStream().read(), "timeout");
            check(System.nanoTime() - t0 >= TimeUnit.MILLISECONDS.toNanos(90), "waited");
            p.hub.writeFrame(WebSocket.OP_BINARY, new byte[] {42});
            eq(42, c.getInputStream().read(), "still usable");
            c.setSoTimeout(0);
            c.fail("done");
        }
    }

    public static void testKeepalive() throws Exception {
        long ping = Conn.pingEveryMs;
        int silence = Conn.linkSilenceMs;
        Conn.pingEveryMs = 100;
        Conn.linkSilenceMs = 400;
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            // the client pings on its own timer, with nobody pinging it
            WebSocket.Frame f = p.hub.readHeader();
            eq(WebSocket.OP_PING, f.op, "a ping");
            // and gives up on a hub that says nothing
            IOException e = throwsA(IOException.class, () -> c.getInputStream().read(), "silence");
            check(e.getMessage().contains("silent"), e.getMessage());
        } finally {
            Conn.pingEveryMs = ping;
            Conn.linkSilenceMs = silence;
        }
        Conn.pingEveryMs = 100;
        Conn.linkSilenceMs = 400;
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            // pings from the hub keep the link alive, and are not answered
            for (int i = 0; i < 8; i++) {
                p.hub.writeFrame(WebSocket.OP_PING, new byte[0]);
                Thread.sleep(100);
            }
            check(c.error() == null, "alive: " + c.error());
            p.hub.writeFrame(WebSocket.OP_BINARY, new byte[] {7});
            eq(7, c.getInputStream().read(), "data");
            for (int i = 0; i < 20; i++) {
                WebSocket.Frame f = p.hub.readHeader();
                p.hub.readPayload(f, 125);
                check(f.op == WebSocket.OP_PING, "only pings from the client, no pongs: " + f.op);
                if (p.hubAvailable() == 0) {
                    break;
                }
            }
            c.fail("done");
        } finally {
            Conn.pingEveryMs = ping;
            Conn.linkSilenceMs = silence;
        }
    }

    public static void testBackpressure() throws Exception {
        try (Pair p = new Pair()) {
            Conn c = new Conn(p.client, new Registry(), "id", Side.CONNECT);
            // a reader that does not read stops the far end, rather than buffering without bound
            byte[] chunk = new byte[64 << 10];
            Thread w = new Thread(() -> {
                try {
                    for (int i = 0; i < 1000; i++) {
                        p.hub.writeFrame(WebSocket.OP_BINARY, chunk);
                    }
                } catch (IOException ignored) {
                    // cut at the end
                }
            });
            w.setDaemon(true);
            w.start();
            Thread.sleep(500);
            check(w.isAlive(), "the hub's writer is held back");
            c.fail("done");
            w.join(5000);
        }
    }
}
