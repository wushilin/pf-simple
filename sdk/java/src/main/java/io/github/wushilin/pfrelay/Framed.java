package io.github.wushilin.pfrelay;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A {@link Transport.Stream} as a {@link Link}: protocol 3's frames
 * (docs/PROTOCOL.md §13.5)
 *
 * <pre>
 *   type (1 byte)  length (2 bytes, big-endian)  payload
 *   0x00 data      0 to 65535                    the next bytes
 *   0x01 eof       0                             the sender's half-close
 *   0x02 err       1 to 1024                     why the stream is dropped
 * </pre>
 *
 * presented as the WebSocket frames they stand for, so that a {@link Conn}
 * works on it exactly as on a WebSocket: data, "eof", "err:why", and the
 * stream's FIN in place of the close. There are no pings: the transport
 * keeps its connection alive, not the stream.
 */
final class Framed implements Link {
    static final int DATA = 0x00;
    static final int EOF = 0x01;
    static final int ERR = 0x02;
    static final int MAX_DATA = 0xFFFF;
    static final int MAX_ERR = 1024;
    /** What an empty reason becomes: a framed err is never empty. */
    static final String NO_REASON = "the peer gave no reason";

    private static final byte[] EOF_TEXT = "eof".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ERR_PREFIX = "err:".getBytes(StandardCharsets.US_ASCII);

    private final Transport.Stream stream;
    private final InputStream in;
    private final OutputStream out;
    private final ReentrantLock wlock = new ReentrantLock();
    private byte[] wbuf = new byte[256];
    private volatile long writeTimeoutMs;
    private final AtomicBoolean finned = new AtomicBoolean();
    private final AtomicBoolean ended = new AtomicBoolean();
    private final AtomicBoolean closing = new AtomicBoolean();
    // what was read, for the rules of §13.5
    private boolean readEOF;
    private boolean readErr;

    Framed(Transport.Stream stream) {
        this.stream = stream;
        this.in = stream.input();
        this.out = stream.output();
    }

    @Override
    public boolean framed() {
        return true;
    }

    @Override
    public void setReadTimeout(int ms) {
        // an idle stream in a live connection stays open as long as it likes (§13.6)
    }

    @Override
    public void setWriteTimeout(long ms) {
        writeTimeoutMs = ms;
    }

    @Override
    public void writeFrame(int op, byte[] p) throws IOException {
        writeFrame(op, p, 0, p.length);
    }

    @Override
    public void writeFrame(int op, byte[] p, int off, int len) throws IOException {
        wlock.lock();
        try {
            writeLocked(op, p, off, len);
        } finally {
            wlock.unlock();
        }
    }

    @Override
    public boolean tryWriteFrame(int op, byte[] p) throws IOException {
        if (op == WebSocket.OP_PING || op == WebSocket.OP_PONG) {
            return true; // the transport keeps the connection alive
        }
        if (!wlock.tryLock()) {
            return false;
        }
        try {
            writeLocked(op, p, 0, p.length);
            return true;
        } finally {
            wlock.unlock();
        }
    }

    private void writeLocked(int op, byte[] p, int off, int len) throws IOException {
        if (ended.get()) {
            throw new SocketException("the connection is closed");
        }
        switch (op) {
            case WebSocket.OP_BINARY:
            case WebSocket.OP_CONT:
                do {
                    int n = Math.min(len, MAX_DATA);
                    writeRaw(DATA, p, off, n);
                    off += n;
                    len -= n;
                } while (len > 0);
                return;
            case WebSocket.OP_TEXT:
                if (len == EOF_TEXT.length && regionEquals(p, off, EOF_TEXT)) {
                    writeRaw(EOF, p, off, 0);
                    return;
                }
                if (len >= ERR_PREFIX.length && regionEquals(p, off, ERR_PREFIX)) {
                    byte[] reason = errPayload(new String(p, off + ERR_PREFIX.length, len - ERR_PREFIX.length,
                            StandardCharsets.UTF_8));
                    writeRaw(ERR, reason, 0, reason.length);
                }
                return; // nothing else is said on a framed stream
            case WebSocket.OP_CLOSE:
                if (finned.compareAndSet(false, true)) {
                    guarded(stream::finish);
                }
                return;
            default:
                return; // pings and pongs: the transport keeps the connection alive
        }
    }

    private static boolean regionEquals(byte[] p, int off, byte[] want) {
        if (p.length - off < want.length) {
            return false;
        }
        for (int i = 0; i < want.length; i++) {
            if (p[off + i] != want[i]) {
                return false;
            }
        }
        return true;
    }

    /** The reason of an err frame: never empty, cut at a UTF-8 boundary to fit. */
    static byte[] errPayload(String reason) {
        if (reason.isEmpty()) {
            reason = NO_REASON;
        }
        byte[] b = reason.getBytes(StandardCharsets.UTF_8);
        if (b.length <= MAX_ERR) {
            return b;
        }
        int n = MAX_ERR;
        while (n > 0 && (b[n] & 0xC0) == 0x80) {
            n--; // b[n] continues a character: cut before the character it belongs to
        }
        byte[] cut = new byte[n];
        System.arraycopy(b, 0, cut, 0, n);
        return cut;
    }

    private interface IoAction {
        void run() throws IOException;
    }

    /** Runs a write, cutting the stream if it takes longer than the write timeout. */
    private void guarded(IoAction a) throws IOException {
        long t = writeTimeoutMs;
        ScheduledFuture<?> watchdog = t > 0 ? Sched.after(t, this::abort) : null;
        try {
            a.run();
        } finally {
            if (watchdog != null) {
                watchdog.cancel(false);
            }
        }
    }

    private void writeRaw(int type, byte[] p, int off, int len) throws IOException {
        int need = 3 + len;
        if (wbuf.length < need) {
            wbuf = new byte[Math.max(need, Math.min(wbuf.length * 2, MAX_DATA + 3))];
        }
        byte[] b = wbuf;
        b[0] = (byte) type;
        b[1] = (byte) (len >>> 8);
        b[2] = (byte) len;
        System.arraycopy(p, off, b, 3, len);
        guarded(() -> {
            out.write(b, 0, need);
            out.flush();
        });
    }

    @Override
    public void beginClose() {
        if (closing.compareAndSet(false, true)) {
            Sched.after(WebSocket.CLOSE_TIMEOUT_MS + 500, this::abort);
        }
    }

    /**
     * Ends the stream: after FIN, the peer has a short while to end its own
     * direction; without FIN, both directions are reset at once.
     */
    @Override
    public void abort() {
        if (ended.compareAndSet(false, true)) {
            stream.close();
        }
    }

    @Override
    public void peerFailed() {
        // §13.5: the end that receives err ends its own direction at once
        if (ended.compareAndSet(false, true)) {
            if (finned.get()) {
                stream.close();
            } else {
                stream.cancel();
            }
        }
    }

    /** The peer broke the protocol: a broken stream, even after the peer's eof (§13.4). */
    static final class BrokenException extends IOException {
        private static final long serialVersionUID = 1L;

        BrokenException(String what) {
            super("the peer broke the protocol: " + what);
        }
    }

    /** The peer broke the protocol: reset the stream ("protocol"), and say so. */
    private IOException broken(String what) {
        if (ended.compareAndSet(false, true)) {
            stream.broken();
        }
        return new BrokenException(what);
    }

    // ---------- reading ----------

    private int readFully(byte[] b, int off, int len) throws IOException {
        int got = 0;
        while (got < len) {
            int n = in.read(b, off + got, len - got);
            if (n < 0) {
                break;
            }
            got += n;
        }
        return got;
    }

    private IOException lost(IOException e) {
        if (e instanceof SocketException || e instanceof EOFException) {
            return e;
        }
        return new SocketException("the stream was lost (" + e.getMessage() + ")");
    }

    @Override
    public WebSocket.Frame readHeader() throws IOException {
        while (true) {
            byte[] h = new byte[3];
            int n;
            try {
                n = readFully(h, 0, 3);
            } catch (IOException e) {
                throw lost(e);
            }
            WebSocket.Frame f = new WebSocket.Frame();
            f.fin = true;
            if (n == 0) { // FIN at a frame boundary: the close
                f.op = WebSocket.OP_CLOSE;
                f.synth = new byte[0];
                return f;
            }
            if (n < 3) {
                throw broken("the stream ended inside a frame");
            }
            int size = ((h[1] & 0xFF) << 8) | (h[2] & 0xFF);
            switch (h[0]) {
                case DATA:
                    if (readErr) {
                        throw broken("a frame after err");
                    }
                    if (readEOF) {
                        throw broken("data after eof");
                    }
                    f.op = WebSocket.OP_BINARY;
                    f.left = size;
                    return f;
                case EOF:
                    if (size != 0) {
                        throw broken("an eof frame with a payload");
                    }
                    if (readEOF || readErr) {
                        throw broken(readErr ? "a frame after err" : "a second eof");
                    }
                    readEOF = true;
                    f.op = WebSocket.OP_TEXT;
                    f.synth = EOF_TEXT.clone();
                    return f;
                case ERR: {
                    if (size == 0 || size > MAX_ERR) {
                        throw broken("an err frame of a bad length");
                    }
                    if (readErr) {
                        throw broken("a frame after err");
                    }
                    byte[] reason = new byte[size];
                    if (readFully(reason, 0, size) < size) {
                        throw broken("the stream ended inside a frame");
                    }
                    readErr = true;
                    byte[] synth = new byte[ERR_PREFIX.length + size];
                    System.arraycopy(ERR_PREFIX, 0, synth, 0, ERR_PREFIX.length);
                    System.arraycopy(reason, 0, synth, ERR_PREFIX.length, size);
                    f.op = WebSocket.OP_TEXT;
                    f.synth = synth;
                    return f;
                }
                default: { // unknown: skipped by its length (§13.5)
                    byte[] skip = new byte[size];
                    if (readFully(skip, 0, size) < size) {
                        throw broken("the stream ended inside a frame");
                    }
                }
            }
        }
    }

    @Override
    public int readBody(WebSocket.Frame f, byte[] p, int off, int len) throws IOException {
        if (len > f.left) {
            len = (int) f.left;
        }
        if (len == 0) {
            return 0;
        }
        int n;
        try {
            n = in.read(p, off, len);
        } catch (IOException e) {
            throw lost(e);
        }
        if (n < 0) {
            throw broken("the stream ended inside a frame");
        }
        f.left -= n;
        return n;
    }

    @Override
    public byte[] readPayload(WebSocket.Frame f, int max) throws IOException {
        if (f.synth != null) {
            if (f.synth.length > max) {
                throw new IOException("a frame larger than " + max + " bytes");
            }
            return f.synth;
        }
        if (f.left > max) {
            throw new IOException("a frame larger than " + max + " bytes");
        }
        byte[] p = new byte[(int) f.left];
        int off = 0;
        while (off < p.length) {
            off += readBody(f, p, off, p.length - off);
        }
        return p;
    }
}
