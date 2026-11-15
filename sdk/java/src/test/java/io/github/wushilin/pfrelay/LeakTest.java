package io.github.wushilin.pfrelay;

import static io.github.wushilin.pfrelay.TestMain.check;
import static io.github.wushilin.pfrelay.TestMain.throwsA;
import static io.github.wushilin.pfrelay.TestMain.waitFor;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

/** Nothing is left holding a socket, a thread or a connection record, however a connection ends. */
public final class LeakTest {
    private LeakTest() {}

    /** The sockets this process has open (Linux); -1 where that cannot be seen. */
    static int sockets() {
        Path fds = Path.of("/proc/self/fd");
        if (!Files.isDirectory(fds)) {
            return -1;
        }
        int n = 0;
        try (Stream<Path> s = Files.list(fds)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                try {
                    if (Files.readSymbolicLink(p).toString().startsWith("socket:")) {
                        n++;
                    }
                } catch (IOException e) {
                    // closed meanwhile
                }
            }
        } catch (IOException e) {
            return -1;
        }
        return n;
    }

    /** Waits until the process has no more sockets open than it had before. */
    static void noMoreSocketsThan(int before, String what) throws InterruptedException {
        if (before < 0) {
            return; // not Linux
        }
        long end = System.nanoTime() + 10_000_000_000L;
        int now = sockets();
        while (now > before && System.nanoTime() < end) {
            Thread.sleep(50);
            now = sockets();
        }
        check(now <= before, what + ": " + (now - before) + " socket(s) left open");
    }

    /** Conn.close() on a stalled link returns, and lets go of the socket and the record. */
    public static void testCloseOnAStalledLink() throws Exception {
        for (boolean useFail : new boolean[] {false, true}) {
            List<WebSocket> held = new CopyOnWriteArrayList<>();
            try (FakeHub hub = new FakeHub(r -> held.add(r.upgrade(Client.H_CONN, "abcdabcdabcdabcd")))) {
                Client c = hub.client().build();
                int before = sockets();
                Conn k = c.dial();
                Thread writer = new Thread(() -> {
                    byte[] b = new byte[64 << 10];
                    try {
                        OutputStream o = k.getOutputStream();
                        while (true) {
                            o.write(b); // the hub never reads: this blocks
                        }
                    } catch (IOException e) {
                        // cut by close
                    }
                });
                writer.setDaemon(true);
                writer.start();
                waitFor("the writer to block", () -> writer.getState() == Thread.State.RUNNABLE
                        && k.info().sent() > 0);
                Thread.sleep(1000);
                check(writer.isAlive(), "the writer is blocked");
                Thread closer = new Thread(useFail ? () -> k.fail("stop") : k::close);
                long t0 = System.nanoTime();
                closer.start();
                closer.join(10_000);
                long took = (System.nanoTime() - t0) / 1_000_000;
                String how = useFail ? "fail()" : "close()";
                check(!closer.isAlive(), how + " on a stalled link did not return");
                check(took < 6000, how + " took " + took + " ms");
                writer.join(5000);
                check(!writer.isAlive(), "the blocked writer was released");
                TestMain.eq(0, c.conns().size(), "no record left");
                TestMain.eq(1L, c.stats().failed(), "a stalled close is a failure");
                for (WebSocket ws : held) {
                    ws.abort(); // the hub's side
                }
                noMoreSocketsThan(before, how + " on a stalled link");
            }
        }
    }

    /** Once serving gives up after having been up, accept() throws why, instead of waiting for ever. */
    public static void testAcceptThrowsAfterGivingUp() throws Exception {
        AtomicInteger n = new AtomicInteger();
        List<WebSocket> ctl = new CopyOnWriteArrayList<>();
        try (FakeHub hub = new FakeHub(r -> {
            if (!r.endpoint.equals("serve")) {
                r.respond(404, null);
            } else if (n.getAndIncrement() == 0) {
                ctl.add(r.upgradeAs(2));
            } else { // a hub from before protocols were announced: too old for the client token
                r.out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        + "Sec-WebSocket-Accept: " + Http.accept(r.headers.get("Sec-WebSocket-Key")) + "\r\n\r\n")
                        .getBytes(StandardCharsets.UTF_8));
                r.out.flush();
            }
        })) {
            Client c = hub.client().clientToken("clienttoken123").timing(TestMain.fastRetry(50, 200)).build();
            Listener l = c.listen();
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            Thread t = new Thread(() -> {
                try {
                    l.accept();
                } catch (Throwable e) {
                    thrown.set(e);
                }
            });
            t.setDaemon(true);
            t.start();
            Thread.sleep(200);
            ctl.get(0).abort(); // the hub goes away; registering again is refused for good
            t.join(5000);
            check(!t.isAlive(), "accept() still waits after serving gave up");
            check(thrown.get() instanceof ProtoException, "accept() threw " + thrown.get());
            check(!l.isUp(), "not up");
            throwsA(ProtoException.class, l::accept, "and again");
        }
    }

    /** A hub that trickles its answer cannot hold a request past the deadline. */
    public static void testRequestDeadline() throws Exception {
        int saved = Http.requestDeadlineMs;
        Http.requestDeadlineMs = 800;
        try (FakeHub hub = new FakeHub(r -> {
            for (int i = 0; i < 100; i++) { // one byte every 100 ms: no read ever times out
                r.out.write('H');
                r.out.flush();
                Thread.sleep(100);
            }
        })) {
            Client c = hub.client().build();
            int before = sockets();
            long t0 = System.nanoTime();
            throwsA(java.net.SocketTimeoutException.class, c::check, "a trickling hub");
            long took = (System.nanoTime() - t0) / 1_000_000;
            check(took < 2500, "the request took " + took + " ms");
            noMoreSocketsThan(before + 1, "after the deadline"); // the hub's side may still be open
        } finally {
            Http.requestDeadlineMs = saved;
        }
    }

    /** Closing a watcher or a listener cuts the request it has in flight. */
    public static void testCloseCutsRequestsInFlight() throws Exception {
        List<Long> sawEnd = new CopyOnWriteArrayList<>();
        try (FakeHub hub = new FakeHub(r -> {
            // never answers: waits for the client to go away
            r.in.read();
            sawEnd.add(System.nanoTime());
        })) {
            Watcher w = hub.client().build().watch();
            waitFor("the check to reach the hub", () -> hub.requests("check").size() == 1);
            long t0 = System.nanoTime();
            w.close();
            waitFor("the hub to see the check end", () -> sawEnd.size() == 1);
            check((sawEnd.get(0) - t0) / 1_000_000 < 2000, "the watcher's check was cut at once");

            Client c = hub.client().build();
            Thread t = new Thread(() -> {
                try {
                    c.listen(java.time.Duration.ofMillis(300)); // times out, and closes itself
                } catch (IOException e) {
                    // expected
                }
            });
            t.start();
            t.join(3000);
            check(!t.isAlive(), "listen(timeout) returned");
            waitFor("the hub to see the registration end", () -> sawEnd.size() == 2);
            check((sawEnd.get(1) - t0) / 1_000_000 < 3000, "the registration in flight was cut");
        }
    }
}
