package io.github.wushilin.pfrelay;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A minimal RFC 6455 WebSocket over an established connection: frames in
 * and out, no extensions. The client side masks what it sends and expects
 * unmasked frames; the server side (used by tests) is the reverse.
 */
final class WebSocket {
    static final int OP_CONT = 0x0;
    static final int OP_TEXT = 0x1;
    static final int OP_BINARY = 0x2;
    static final int OP_CLOSE = 0x8;
    static final int OP_PING = 0x9;
    static final int OP_PONG = 0xA;

    static final long CLOSE_TIMEOUT_MS = 3000;

    private final Socket socket; // for read timeouts
    private final Socket raw; // closed to abort
    private final InputStream in;
    private final OutputStream out;
    private final boolean client;
    /** The hub's handshake answer, on a dialed connection; names are case-insensitive. */
    final Map<String, String> header;

    private final ReentrantLock wlock = new ReentrantLock();
    private byte[] wbuf = new byte[256];
    private volatile long writeTimeoutMs;
    private final AtomicBoolean aborted = new AtomicBoolean();
    private final AtomicBoolean closing = new AtomicBoolean();

    WebSocket(Socket socket, Socket raw, InputStream in, OutputStream out, boolean client, Map<String, String> header) {
        this.socket = socket;
        this.raw = raw;
        this.in = in;
        this.out = out;
        this.client = client;
        this.header = header == null ? Map.of() : header;
    }

    /** How long the peer may stay silent; 0 means no limit. */
    void setReadTimeout(int ms) throws SocketException {
        socket.setSoTimeout(ms);
    }

    /** How long one frame write may take before the connection is cut; 0 means no limit. */
    void setWriteTimeout(long ms) {
        writeTimeoutMs = ms;
    }

    void writeFrame(int op, byte[] p) throws IOException {
        writeFrame(op, p, 0, p.length);
    }

    void writeFrame(int op, byte[] p, int off, int len) throws IOException {
        wlock.lock();
        try {
            writeLocked(op, p, off, len);
        } finally {
            wlock.unlock();
        }
    }

    /**
     * Writes a frame unless another write is in progress, which says the
     * link is in use anyway. Returns whether it wrote. For keepalive pings,
     * which must never queue up behind a write that the network holds back.
     */
    boolean tryWriteFrame(int op, byte[] p) throws IOException {
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
        if (aborted.get()) {
            throw new SocketException("the connection is closed");
        }
        int need = 14 + len;
        if (wbuf.length < need) {
            wbuf = new byte[Math.max(need, Math.min(wbuf.length * 2, 70 << 10))];
        }
        byte[] b = wbuf;
        int n = 0;
        b[n++] = (byte) (0x80 | op); // FIN
        int maskBit = client ? 0x80 : 0;
        if (len < 126) {
            b[n++] = (byte) (maskBit | len);
        } else if (len <= 0xFFFF) {
            b[n++] = (byte) (maskBit | 126);
            b[n++] = (byte) (len >>> 8);
            b[n++] = (byte) len;
        } else {
            b[n++] = (byte) (maskBit | 127);
            long l = len;
            for (int k = 7; k >= 0; k--) {
                b[n++] = (byte) (l >>> (8 * k));
            }
        }
        if (client) {
            int m = ThreadLocalRandom.current().nextInt();
            byte m0 = (byte) (m >>> 24), m1 = (byte) (m >>> 16), m2 = (byte) (m >>> 8), m3 = (byte) m;
            b[n++] = m0;
            b[n++] = m1;
            b[n++] = m2;
            b[n++] = m3;
            byte[] mask = {m0, m1, m2, m3};
            for (int k = 0; k < len; k++) {
                b[n + k] = (byte) (p[off + k] ^ mask[k & 3]);
            }
        } else {
            System.arraycopy(p, off, b, n, len);
        }
        n += len;
        long t = writeTimeoutMs;
        ScheduledFuture<?> watchdog = t > 0 ? Sched.after(t, this::abort) : null;
        try {
            out.write(b, 0, n);
            out.flush();
        } finally {
            if (watchdog != null) {
                watchdog.cancel(false);
            }
        }
    }

    /**
     * Bounds what is left of this connection: from now on it is cut after
     * {@link #CLOSE_TIMEOUT_MS}, whatever is still writing or waiting.
     */
    void beginClose() {
        if (closing.compareAndSet(false, true)) {
            Sched.after(CLOSE_TIMEOUT_MS + 500, this::abort);
        }
    }

    /** Cuts the connection at once; whatever blocks on it fails. */
    void abort() {
        if (aborted.compareAndSet(false, true)) {
            try {
                raw.close();
            } catch (IOException ignored) {
                // nothing more to do
            }
            if (socket != raw) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // the raw socket is closed: nothing more to do
                }
            }
        }
    }

    boolean isAborted() {
        return aborted.get();
    }

    /** The header of the frame being read; left and at track its payload. */
    static final class Frame {
        int op;
        boolean fin;
        long left;
        boolean masked;
        final byte[] mask = new byte[4];
        int at;
    }

    private int readByte() throws IOException {
        int c = in.read();
        if (c < 0) {
            throw new EOFException("the connection ended");
        }
        return c;
    }

    Frame readHeader() throws IOException {
        int b0 = readByte();
        int b1 = readByte();
        Frame f = new Frame();
        if ((b0 & 0x70) != 0) {
            throw new IOException("a frame with reserved bits set");
        }
        f.fin = (b0 & 0x80) != 0;
        f.op = b0 & 0x0F;
        f.masked = (b1 & 0x80) != 0;
        if (f.masked == client) {
            throw new IOException(client ? "a masked frame from the server" : "an unmasked frame from the client");
        }
        long len = b1 & 0x7F;
        if (len == 126) {
            len = ((long) readByte() << 8) | readByte();
        } else if (len == 127) {
            len = 0;
            for (int k = 0; k < 8; k++) {
                len = (len << 8) | readByte();
            }
            if (len < 0) {
                throw new IOException("a frame of impossible length");
            }
        }
        f.left = len;
        if (f.masked) {
            for (int k = 0; k < 4; k++) {
                f.mask[k] = (byte) readByte();
            }
        }
        return f;
    }

    /** Reads some of the frame's remaining payload; at least one byte if any is left. */
    int readBody(Frame f, byte[] p, int off, int len) throws IOException {
        if (len > f.left) {
            len = (int) f.left;
        }
        if (len == 0) {
            return 0;
        }
        int n = in.read(p, off, len);
        if (n < 0) {
            throw new EOFException("the connection ended in the middle of a frame");
        }
        if (f.masked) {
            for (int k = 0; k < n; k++) {
                p[off + k] ^= f.mask[(f.at + k) & 3];
            }
            f.at = (f.at + n) & 3;
        }
        f.left -= n;
        return n;
    }

    /** Reads the whole payload of a frame, which may be at most max bytes. */
    byte[] readPayload(Frame f, int max) throws IOException {
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
