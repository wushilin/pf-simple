package io.github.wushilin.pfrelay;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * One connection through a tunnel: a stream of bytes each way, with
 * half-close, and a reason when it fails (docs/PROTOCOL.md §8).
 *
 * <p>The input stream returns -1 when the far end half-closes, and throws a
 * {@link RemoteException} when the far end or the hub dropped the
 * connection with a reason. {@link #shutdownOutput()} half-closes this end;
 * {@link #close()} half-closes first if that was not done, much as closing a
 * TCP socket sends its FIN.
 *
 * <p>The hub may pass on a failure of the far end as a half-close first, so
 * the input stream returns -1 and the reason arrives just after it:
 * {@link #error()} reports it then.
 *
 * <p>A Conn is safe for one reader and one writer at a time, on different
 * threads.
 */
public final class Conn implements Closeable {
    static final int CHUNK = 64 << 10;
    static final int MAX_DATA_FRAME = 1 << 20;
    static final int MAX_TEXT_FRAME = 1024;
    private static final byte[] EOF_TEXT = "eof".getBytes(StandardCharsets.US_ASCII);
    private static final Object EOF_MARK = new Object();

    private final WebSocket ws;
    private final Client client;
    private final Registry.Record rec;
    private final int linkSilenceMs;

    // reading: the reader thread hands chunks over, at most a few ahead
    private final ArrayBlockingQueue<Object> chunks = new ArrayBlockingQueue<>(4);
    private final ReentrantLock rlock = new ReentrantLock();
    private byte[] pending;
    private int pendingOff;
    private boolean readDone; // -1 was handed out
    private IOException readErr;
    private volatile int soTimeout;

    private final AtomicBoolean readEOF = new AtomicBoolean();
    private final AtomicBoolean wroteEOF = new AtomicBoolean();
    private final AtomicBoolean failed = new AtomicBoolean();
    private final AtomicReference<IOException> failure = new AtomicReference<>(); // what the reader saw
    private final AtomicReference<IOException> broke = new AtomicReference<>(); // what broke it here
    private volatile String goneReason;
    private final CountDownLatch gone = new CountDownLatch(1); // the reader has stopped, for whatever reason
    // Reuse (protocol 2, docs/PROTOCOL.md §12): the registration whose idle
    // pool this leg may join; null when the hub did not offer reuse.
    private final Registration reuse;
    private final long verdictMs;
    private final AtomicBoolean idled = new AtomicBoolean(); // the reader stopped at the hub's "idle"
    private volatile boolean closed; // close has begun: errors from here on are our own doing
    private final AtomicBoolean closeOnce = new AtomicBoolean();
    private final AtomicBoolean sentClose = new AtomicBoolean();
    private final ReentrantLock wlock = new ReentrantLock(); // orders data before eof
    private final ScheduledFuture<?> pinger;

    private final InputStream input = new In();
    private final OutputStream output = new Out();

    /** Takes over ws, and reports the connection opened. */
    Conn(WebSocket ws, Client client, ConnId id, Side side) throws IOException {
        this(ws, client, id, side, null);
    }

    /**
     * Takes over ws, and reports the connection opened. reuse is the
     * registration whose idle pool the leg may join, when the hub offered
     * reuse on it; null otherwise.
     */
    Conn(WebSocket ws, Client client, ConnId id, Side side, Registration reuse) throws IOException {
        this.ws = ws;
        this.client = client;
        this.reuse = reuse;
        Timing timing = client.timing();
        this.verdictMs = timing.verdictMs();
        this.linkSilenceMs = timing.linkSilenceMs();
        ws.setWriteTimeout(0); // data may be held back by the network for as long as it likes
        ws.setReadTimeout(linkSilenceMs);
        this.rec = client.registry.add(id, side);
        rec.conn = this;
        // Pings come from a timer of their own, not in reply to the peer's, so
        // reading never has to write and the two directions stay independent.
        pinger = Sched.every(timing.pingEveryMs(), () -> {
            try {
                ws.tryWriteFrame(WebSocket.OP_PING, new byte[0]);
            } catch (IOException e) {
                ws.abort(); // wake whoever is reading
            }
        });
        Sched.go(this::readLoop);
        client.opened(rec);
    }

    /** The hub's id for this connection, the same on both ends. */
    public ConnId id() {
        return rec.id;
    }

    /** A snapshot of this connection. */
    public ConnInfo info() {
        return rec.info();
    }

    /**
     * The bytes from the far end. read returns -1 after the far end's
     * half-close; it throws a {@link RemoteException} with the reason when
     * the far end or the hub dropped the connection, and an IOException when
     * the link was lost. Closing it does nothing: close the Conn.
     */
    public InputStream getInputStream() {
        return input;
    }

    /**
     * The bytes to the far end. Each write of up to 64 KiB is one frame.
     * Closing it half-closes, as {@link #shutdownOutput()} does.
     */
    public OutputStream getOutputStream() {
        return output;
    }

    /**
     * How long a read waits for data before it throws a
     * {@link SocketTimeoutException}, in milliseconds; 0 (the default) means
     * for ever. A read that times out leaves the connection usable.
     */
    public void setSoTimeout(int ms) {
        if (ms < 0) {
            throw new IllegalArgumentException("negative timeout");
        }
        soTimeout = ms;
    }

    public int getSoTimeout() {
        return soTimeout;
    }

    /** Whether this end has half-closed. */
    public boolean wroteEof() {
        return wroteEOF.get();
    }

    /** Whether the far end has half-closed. */
    public boolean readEof() {
        return readEOF.get();
    }

    /**
     * Half-closes: the far end reads the end of the stream after what was
     * written so far, and may go on sending. Writing after this fails.
     */
    public void shutdownOutput() throws IOException {
        wlock.lock();
        try {
            if (wroteEOF.compareAndSet(false, true)) {
                ws.writeFrame(WebSocket.OP_TEXT, EOF_TEXT);
            }
        } catch (IOException e) {
            broke(e);
            throw e;
        } finally {
            wlock.unlock();
        }
    }

    /**
     * The half-close that close() sends first. It waits at most
     * CLOSE_TIMEOUT_MS for a writer to let go, and bounds its own write the
     * same, without beginning to close the leg, which may yet be reused.
     * Returns false when the link is stalled.
     */
    private boolean halfCloseForClose() {
        try {
            if (!wlock.tryLock(WebSocket.CLOSE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                broke(new IOException("the link to the server stalled: a write did not finish in "
                        + WebSocket.CLOSE_TIMEOUT_MS / 1000 + "s"));
                return false;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            broke(new java.io.InterruptedIOException("interrupted while closing"));
            return false;
        }
        try {
            if (wroteEOF.compareAndSet(false, true)) {
                ws.setWriteTimeout(WebSocket.CLOSE_TIMEOUT_MS);
                ws.writeFrame(WebSocket.OP_TEXT, EOF_TEXT);
            }
            return true;
        } catch (IOException e) {
            broke(e);
            return true; // failed is set: close goes on as for a failure
        } finally {
            wlock.unlock();
        }
    }

    /** Records the first error that broke the connection on this side. */
    private void broke(IOException e) {
        failed.set(true);
        broke.compareAndSet(null, e);
    }

    /**
     * Why the connection failed, once that is known: the far end's or the
     * hub's reason (a {@link RemoteException}), or a lost link. Null while
     * it is fine and after a clean finish. It can say more than the input
     * stream did: a reason may arrive after the far end's half-close.
     */
    public IOException error() {
        IOException f = failure.get();
        if (f != null) {
            return f;
        }
        String r = goneReason;
        if (r != null) {
            return new RemoteException(r);
        }
        return null;
    }

    /**
     * Drops the connection and tells the far end why: its read throws a
     * {@link RemoteException} with this reason.
     */
    public void fail(String reason) {
        failWith(reason, new DroppedException(reason));
    }

    /** Drops the connection, telling the far end reason; cause is how it ended here. */
    void failWith(String reason, IOException cause) {
        broke(cause);
        if (!closeOnce.compareAndSet(false, true)) {
            return;
        }
        closed = true;
        pinger.cancel(false);
        ws.beginClose();
        try {
            if (sentClose.compareAndSet(false, true)) { // nothing may follow a close frame
                ws.writeFrame(WebSocket.OP_TEXT, ("err:" + cleanReason(reason == null ? "" : reason, 200))
                        .getBytes(StandardCharsets.UTF_8));
                ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
            }
        } catch (IOException ignored) {
            // the link is gone already
        }
        ws.abort();
        client.closed(rec, broke.get());
    }

    /**
     * Drops the stream for {@link Client#drop}: the far end hears reason,
     * and this end's reads and writes fail from now on. The connection is
     * retired, and reported closed, when whoever holds it closes it.
     */
    void cut(String reason) {
        failed.set(true);
        closed = true;
        pinger.cancel(false);
        ws.beginClose();
        Sched.go(() -> {
            try {
                if (sentClose.compareAndSet(false, true)) {
                    ws.writeFrame(WebSocket.OP_TEXT, ("err:" + cleanReason(reason, 200))
                            .getBytes(StandardCharsets.UTF_8));
                    ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                }
            } catch (IOException ignored) {
                // the link is gone already
            }
            ws.abort();
        });
    }

    /** Cuts the connection without a word to the far end; cause is how it ended here. */
    void abortWith(IOException cause) {
        broke(cause);
        close();
    }

    /** Whether the far end is gone for good: it closed the stream, or the link died. */
    boolean isGone() {
        return gone.getCount() == 0 && !idled.get();
    }

    /** Whether the hub offered to reuse this connection's leg. */
    boolean reusable() {
        return reuse != null;
    }

    /** What the far end said when it went, after its half-close; null if nothing. */
    String goneReason() {
        return goneReason;
    }

    /**
     * Ends the connection. If this end has not half-closed, it does so
     * first. When both ends had half-closed, this is a clean finish: the
     * WebSocket closing handshake, waiting up to 3 seconds for the far end's
     * close. Otherwise the far end sees the connection cut.
     */
    @Override
    public void close() {
        if (!closeOnce.compareAndSet(false, true)) {
            return;
        }
        if (!wroteEOF.get() && !failed.get() && !halfCloseForClose()) {
            // a writer is stuck behind a stalled link: cut it, and every write with it
            closed = true;
            pinger.cancel(false);
            ws.beginClose();
            ws.abort();
            client.closed(rec, broke.get());
            return;
        }
        closed = true;
        pinger.cancel(false);
        if (reuse != null && readEOF.get() && wroteEOF.get() && !failed.get() && failure.get() == null
                && broke.get() == null && goneReason == null) {
            finishOffered();
            return;
        }
        ws.beginClose();
        if (readEOF.get() && wroteEOF.get() && !failed.get()) {
            boolean wrote = true;
            if (sentClose.compareAndSet(false, true)) {
                try {
                    ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                } catch (IOException e) {
                    wrote = false;
                }
            }
            if (wrote) {
                try {
                    gone.await(WebSocket.CLOSE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        ws.abort();
        IOException err = broke.get();
        client.closed(rec, err != null ? err : error());
    }

    /**
     * Ends a clean finish on a leg the hub offered to reuse: waits for the
     * hub's verdict, keeps the leg if there is room, and only then reports
     * the connection closed (docs/PROTOCOL.md §12.5).
     */
    private void finishOffered() {
        try {
            gone.await(verdictMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (idled.get()) {
            // The reader has stopped at the hub's "idle": nobody reads the leg now.
            if (reuse.keep()) {
                try {
                    ws.setWriteTimeout(Client.CONTROL_WRITE_TIMEOUT_MS); // the leg is no longer carrying data
                    ws.writeFrame(WebSocket.OP_TEXT, Registration.IDLE_TEXT);
                    client.closed(rec, null);
                    reuse.idleLeg(ws);
                    return;
                } catch (IOException e) {
                    reuse.release();
                }
            }
            // over the cap: the hub's "idle" is answered with a close, and
            // nobody will answer ours
            ws.beginClose();
            if (sentClose.compareAndSet(false, true)) {
                try {
                    ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                } catch (IOException ignored) {
                    // going anyway
                }
            }
            ws.abort();
            client.closed(rec, null);
            return;
        }
        if (gone.getCount() == 0 && goneReason != null) { // err: instead of idle: the connection failed
            ws.abort();
            client.closed(rec, new RemoteException(goneReason));
            return;
        }
        // the hub closed, or said nothing in time: protocol 1 rules (§8.4)
        ws.beginClose();
        if (sentClose.compareAndSet(false, true)) {
            try {
                ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                gone.await(WebSocket.CLOSE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            } catch (IOException ignored) {
                // going anyway
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        ws.abort();
        IOException err = broke.get();
        client.closed(rec, err != null ? err : error());
    }

    // ---------- the reader thread ----------

    private void readLoop() {
        try {
            while (true) {
                WebSocket.Frame f = ws.readHeader();
                switch (f.op) {
                    case WebSocket.OP_BINARY:
                    case WebSocket.OP_CONT:
                        if (f.left > MAX_DATA_FRAME) {
                            throw new IOException("the server sent a data frame larger than 1 MiB");
                        }
                        if (readEOF.get()) {
                            // nothing may follow a half-close: a broken or hostile peer
                            if (!closed) {
                                failure.compareAndSet(null,
                                        new IOException("the server sent data after the far end's half-close"));
                            }
                            return;
                        }
                        while (f.left > 0) {
                            byte[] b = new byte[(int) Math.min(f.left, CHUNK)];
                            int off = 0;
                            while (off < b.length) {
                                off += ws.readBody(f, b, off, b.length - off);
                            }
                            deliver(b);
                        }
                        break;
                    case WebSocket.OP_TEXT: {
                        String msg = new String(ws.readPayload(f, MAX_TEXT_FRAME), StandardCharsets.UTF_8);
                        if (reuse != null && readEOF.get() && msg.equals(Registration.IDLE)) {
                            // The hub's verdict: a clean finish. Valid only once this
                            // side sent its eof (§12.4); otherwise a violation.
                            if (wroteEOF.get()) {
                                idled.set(true);
                                return; // stop reading: the leg may go on to its next connection
                            }
                            if (!closed) {
                                failure.compareAndSet(null,
                                        new IOException("the server sent idle before this side's half-close"));
                            }
                            ws.abort();
                            return;
                        }
                        if (msg.equals("eof")) {
                            if (readEOF.compareAndSet(false, true)) {
                                deliver(EOF_MARK);
                            }
                        } else if (msg.startsWith("err:")) {
                            String reason = cleanReason(msg.substring(4), 200);
                            if (readEOF.get()) {
                                goneReason = reason; // a finish that turns out to be a failure
                            } else {
                                failRead(new RemoteException(reason));
                                return;
                            }
                        }
                        break;
                    }
                    case WebSocket.OP_CLOSE: {
                        byte[] p = ws.readPayload(f, 125);
                        if (!readEOF.get()) {
                            // without both half-closes, a close is a broken stream (§8.4)
                            failRead(new IOException("the server closed the connection"));
                        }
                        if (sentClose.compareAndSet(false, true)) {
                            // answer the close, as RFC 6455 asks
                            try {
                                byte[] code = new byte[Math.min(p.length, 2)];
                                System.arraycopy(p, 0, code, 0, code.length);
                                if (!ws.tryWriteFrame(WebSocket.OP_CLOSE, code)) {
                                    sentClose.set(false);
                                }
                            } catch (IOException ignored) {
                                // the link is going anyway
                            }
                        }
                        return;
                    }
                    case WebSocket.OP_PING:
                    case WebSocket.OP_PONG:
                        ws.readPayload(f, 125); // keepalive; never answered on a stream
                        break;
                    default:
                        throw new IOException("the server sent a frame of unknown type " + f.op);
                }
            }
        } catch (SocketTimeoutException e) {
            lost(new SocketTimeoutException("the link to the server was silent for "
                    + (linkSilenceMs / 1000) + "s"));
        } catch (IOException e) {
            lost(e);
        } finally {
            pinger.cancel(false); // nothing more to keep alive
            gone.countDown();
        }
    }

    private void lost(IOException e) {
        if (readEOF.get()) {
            return; // after the far end's half-close, nothing more was due
        }
        if (e instanceof SocketTimeoutException) {
            failRead(e);
        } else if (e instanceof SocketException || e instanceof java.io.EOFException) {
            failRead(new IOException("the link to the server was lost (" + e.getMessage() + ")", e));
        } else {
            failRead(e);
        }
    }

    private void failRead(IOException e) {
        if (closed) {
            return;
        }
        failure.compareAndSet(null, e);
        deliver(e);
    }

    /** Hands o to the reader, waiting while it is behind; drops it once the Conn is closed. */
    private void deliver(Object o) {
        try {
            while (!closed) {
                if (chunks.offer(o, 200, TimeUnit.MILLISECONDS)) {
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Makes a reason that arrived over the wire safe to log and pass on:
     * printable characters only, at most max of them.
     */
    static String cleanReason(String s, int max) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length() && b.length() < max;) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (cp >= 0x20 && cp != 0x7F && !Character.isISOControl(cp)
                    && Character.getType(cp) != Character.FORMAT
                    && Character.getType(cp) != Character.UNASSIGNED
                    && Character.getType(cp) != Character.SURROGATE
                    && Character.getType(cp) != Character.PRIVATE_USE
                    && (cp == ' ' || !Character.isWhitespace(cp))) {
                b.appendCodePoint(cp);
            }
        }
        return b.toString();
    }

    // ---------- the streams ----------

    private int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }
        rlock.lock();
        try {
            while (pending == null) {
                if (readDone) {
                    return -1;
                }
                if (readErr != null) {
                    throw readErr;
                }
                if (closed) {
                    throw new SocketException("the connection is closed");
                }
                int t = soTimeout;
                long deadline = t > 0 ? System.nanoTime() + t * 1_000_000L : 0;
                Object o = null;
                while (o == null) {
                    long wait = 200;
                    if (t > 0) {
                        long left = (deadline - System.nanoTime()) / 1_000_000L;
                        if (left <= 0) {
                            throw new SocketTimeoutException("read timed out");
                        }
                        wait = Math.min(wait, left);
                    }
                    try {
                        o = chunks.poll(wait, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new InterruptedIOException("interrupted");
                    }
                    if (o == null && closed) {
                        throw new SocketException("the connection is closed");
                    }
                }
                if (o == EOF_MARK) {
                    readDone = true;
                } else if (o instanceof IOException) {
                    readErr = (IOException) o;
                    broke(readErr);
                } else {
                    byte[] chunk = (byte[]) o;
                    if (chunk.length > 0) {
                        pending = chunk;
                        pendingOff = 0;
                    }
                }
            }
            int n = Math.min(len, pending.length - pendingOff);
            System.arraycopy(pending, pendingOff, b, off, n);
            pendingOff += n;
            if (pendingOff == pending.length) {
                pending = null;
            }
            rec.received.addAndGet(n);
            return n;
        } finally {
            rlock.unlock();
        }
    }

    private void write(byte[] b, int off, int len) throws IOException {
        wlock.lock();
        try {
            if (closed) {
                throw new SocketException("the connection is closed");
            }
            if (wroteEOF.get()) {
                throw new IOException("write after shutdownOutput");
            }
        } catch (IOException e) {
            wlock.unlock();
            throw e; // a mistake of the caller's, not a failure of the connection
        }
        try {
            for (int at = 0; at < len; at += CHUNK) {
                int n = Math.min(CHUNK, len - at);
                ws.writeFrame(WebSocket.OP_BINARY, b, off + at, n);
                rec.sent.addAndGet(n);
            }
        } catch (IOException e) {
            broke(e);
            throw e;
        } finally {
            wlock.unlock();
        }
    }

    private final class In extends InputStream {
        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n;
            do {
                n = Conn.this.read(one, 0, 1);
            } while (n == 0);
            return n < 0 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            java.util.Objects.checkFromIndexSize(off, len, b.length);
            return Conn.this.read(b, off, len);
        }

        @Override
        public int available() {
            rlock.lock();
            try {
                return pending == null ? 0 : pending.length - pendingOff;
            } finally {
                rlock.unlock();
            }
        }

        @Override
        public void close() {
            // the Conn is closed with Conn.close
        }
    }

    private final class Out extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            Conn.this.write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            java.util.Objects.checkFromIndexSize(off, len, b.length);
            Conn.this.write(b, off, len);
        }

        @Override
        public void close() throws IOException {
            shutdownOutput();
        }
    }

    @Override
    public String toString() {
        return "Conn[" + rec.id + ", " + rec.side + "]";
    }
}
