package io.github.wushilin.pfrelay;

import static io.github.wushilin.pfrelay.TestMain.check;
import static io.github.wushilin.pfrelay.TestMain.eq;
import static io.github.wushilin.pfrelay.TestMain.throwsA;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Protocol 3's frames (docs/PROTOCOL.md §13.5) as a {@link Framed} link
 * presents them, and a {@link Conn} over a {@link Transport}: the seam
 * pfrelay-quic plugs QUIC into.
 */
public final class FramedTest {
    private FramedTest() {}

    /** A transport stream over pipes; the test plays the hub at the other end. */
    static final class FakeStream implements Transport.Stream {
        final PipedInputStream in = new PipedInputStream(1 << 20);
        final PipedOutputStream out = new PipedOutputStream();
        final PipedOutputStream peerOut; // what the hub writes, this side reads
        final DataInputStream peerIn; // what this side writes
        volatile boolean finished;
        volatile String ended; // "cancel", "broken" or "close"

        FakeStream() throws IOException {
            peerOut = new PipedOutputStream(in);
            PipedInputStream pin = new PipedInputStream(out, 1 << 20);
            peerIn = new DataInputStream(pin);
        }

        @Override
        public InputStream input() {
            return in;
        }

        @Override
        public OutputStream output() {
            return out;
        }

        @Override
        public void finish() throws IOException {
            finished = true;
            out.close();
        }

        @Override
        public void cancel() {
            ended = ended == null ? "cancel" : ended;
        }

        @Override
        public void broken() {
            ended = ended == null ? "broken" : ended;
        }

        @Override
        public void close() {
            ended = ended == null ? "close" : ended;
        }

        void peer(int type, byte[] p) throws IOException {
            peerOut.write(frame(type, p));
            peerOut.flush();
        }

        /** The next frame this side sent, as type and payload; null at its FIN. */
        Object[] next() throws IOException {
            int t = peerIn.read();
            if (t < 0) {
                return null;
            }
            int n = peerIn.readUnsignedShort();
            byte[] p = new byte[n];
            peerIn.readFully(p);
            return new Object[] {t, p};
        }
    }

    static byte[] frame(int type, byte[] p) {
        byte[] b = new byte[3 + p.length];
        b[0] = (byte) type;
        b[1] = (byte) (p.length >>> 8);
        b[2] = (byte) p.length;
        System.arraycopy(p, 0, b, 3, p.length);
        return b;
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** A stream that reads fixed bytes and writes into a buffer. */
    static final class Fixed implements Transport.Stream {
        final InputStream in;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        volatile boolean finished;
        volatile String ended;

        Fixed(byte[] in) {
            this.in = new ByteArrayInputStream(in);
        }

        @Override
        public InputStream input() {
            return in;
        }

        @Override
        public OutputStream output() {
            return out;
        }

        @Override
        public void finish() {
            finished = true;
        }

        @Override
        public void cancel() {
            ended = "cancel";
        }

        @Override
        public void broken() {
            ended = "broken";
        }

        @Override
        public void close() {
            ended = "close";
        }
    }

    public static void testFramedWrites() throws Exception {
        Fixed s = new Fixed(new byte[0]);
        Framed f = new Framed(s);
        byte[] data = new byte[70_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        f.writeFrame(WebSocket.OP_BINARY, data);
        f.writeFrame(WebSocket.OP_PING, new byte[0]); // no pings on a framed stream
        f.writeFrame(WebSocket.OP_TEXT, utf8("eof"));
        f.writeFrame(WebSocket.OP_TEXT, utf8("err:"));
        f.writeFrame(WebSocket.OP_TEXT, utf8("hello")); // nothing else is said
        check(!s.finished, "no FIN yet");
        f.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
        check(s.finished, "the close is FIN");
        ByteArrayOutputStream want = new ByteArrayOutputStream();
        want.write(frame(0, java.util.Arrays.copyOfRange(data, 0, 65535)));
        want.write(frame(0, java.util.Arrays.copyOfRange(data, 65535, 70_000)));
        want.write(frame(1, new byte[0]));
        want.write(frame(2, utf8(Framed.NO_REASON)));
        check(java.util.Arrays.equals(want.toByteArray(), s.out.toByteArray()),
                "data split at 65535, eof, and an empty err given a reason");
        throwsA(IOException.class, () -> {
            f.abort();
            f.writeFrame(WebSocket.OP_BINARY, data);
        }, "nothing is written after the stream ended");
    }

    public static void testFramedErrIsCutAtACharacter() {
        String reason = "x" + "é".repeat(600); // 1201 bytes
        byte[] b = Framed.errPayload(reason);
        check(b.length <= Framed.MAX_ERR && b.length == 1023, "cut to fit, before a split character: " + b.length);
        eq(reason.substring(0, 512), new String(b, StandardCharsets.UTF_8), "whole characters");
    }

    public static void testFramedReads() throws Exception {
        ByteArrayOutputStream in = new ByteArrayOutputStream();
        in.write(frame(0, utf8("hi")));
        in.write(frame(0x7f, utf8("skip me"))); // unknown: skipped by its length
        in.write(frame(1, new byte[0]));
        in.write(frame(2, utf8("boom")));
        Framed f = new Framed(new Fixed(in.toByteArray()));
        WebSocket.Frame h = f.readHeader();
        eq(WebSocket.OP_BINARY, h.op, "data");
        byte[] two = new byte[2];
        eq(2, f.readBody(h, two, 0, 2), "its bytes");
        eq("hi", new String(two, StandardCharsets.UTF_8), "data");
        h = f.readHeader();
        eq("eof", new String(f.readPayload(h, 1024), StandardCharsets.UTF_8), "eof, after the unknown frame");
        h = f.readHeader();
        eq(WebSocket.OP_TEXT, h.op, "err");
        eq("err:boom", new String(f.readPayload(h, 1024), StandardCharsets.UTF_8), "err");
        h = f.readHeader();
        eq(WebSocket.OP_CLOSE, h.op, "FIN at a frame boundary is the close");
    }

    public static void testFramedBreaks() throws Exception {
        byte[][] bad = {
            concat(frame(1, new byte[0]), frame(0, utf8("late"))), // data after eof
            concat(frame(1, new byte[0]), frame(1, new byte[0])), // a second eof
            new byte[] {0, 0, 5, 'a'}, // FIN inside a frame
            new byte[] {0, 0}, // FIN inside a header
            frame(2, new byte[0]), // an empty err
            frame(1, utf8("x")), // eof with a payload
        };
        for (byte[] b : bad) {
            Fixed s = new Fixed(b);
            Framed f = new Framed(s);
            throwsA(IOException.class, () -> {
                while (true) {
                    WebSocket.Frame h = f.readHeader();
                    if (h.op == WebSocket.OP_CLOSE) {
                        return;
                    }
                    f.readPayload(h, 1 << 16);
                }
            }, "a broken stream");
            eq("broken", s.ended, "the stream is reset (protocol)");
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /** A transport whose connect hands out one stream. */
    static final class OneStream implements Transport {
        final FakeStream s;

        OneStream(FakeStream s) {
            this.s = s;
        }

        @Override
        public String name() {
            return "test";
        }

        @Override
        public Registration register(Params p, String target) throws IOException {
            throw new IOException("not here");
        }

        @Override
        public Dialed connect(Params p) {
            return new Dialed(s, "0123456789abcdef");
        }

        @Override
        public void check(Params p) {}

        @Override
        public void close() {}
    }

    static Client client(Transport t, ClientEvents ev) {
        return Client.builder().server("https://127.0.0.1:1").word("aaaa-bbbb-cccc").transport(t).events(ev).build();
    }

    public static void testConnOverATransport() throws Exception {
        FakeStream s = new FakeStream();
        AtomicReference<IOException> closedWith = new AtomicReference<>(new IOException("not closed"));
        CountDownLatch closed = new CountDownLatch(1);
        Client c = client(new OneStream(s), new ClientEvents() {
            @Override
            public void onClose(ConnInfo info, IOException error) {
                closedWith.set(error);
                closed.countDown();
            }
        });
        Conn conn = c.dial();
        eq("0123456789abcdef", conn.id().toString(), "the hub's id");
        conn.getOutputStream().write(utf8("hello"));
        conn.shutdownOutput();
        Object[] f = s.next();
        eq(0, f[0], "data");
        eq("hello", new String((byte[]) f[1], StandardCharsets.UTF_8), "data");
        eq(1, s.next()[0], "eof");
        s.peer(0, utf8("world"));
        s.peer(1, new byte[0]);
        eq("world", new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8), "read to the eof");
        Thread closer = new Thread(conn::close);
        closer.start();
        check(s.next() == null, "FIN after both eofs");
        s.peerOut.close(); // the hub's FIN
        closer.join(5000);
        check(closed.await(5, TimeUnit.SECONDS), "reported closed");
        eq(null, closedWith.get(), "a clean finish");
        eq("close", s.ended, "the stream is let go after FIN, not reset");
    }

    public static void testErrOverATransport() throws Exception {
        FakeStream s = new FakeStream();
        Client c = client(new OneStream(s), new ClientEvents() {});
        Conn conn = c.dial();
        s.peer(2, utf8("the target went away"));
        RemoteException e = throwsA(RemoteException.class, () -> conn.getInputStream().read(), "the reason");
        eq("the target went away", e.reason(), "the reason");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (s.ended == null && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        eq("cancel", s.ended, "the end that receives err ends its direction at once");
        conn.close();
    }
}
