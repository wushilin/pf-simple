package io.github.wushilin.pfrelayquic;

import io.github.wushilin.pfrelay.Transport;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import tech.kwik.core.QuicStream;

/**
 * One QUIC stream to the hub, from its request (or the hub's open) to its
 * end in both directions (docs/PROTOCOL.md §13.5): finish sends FIN, and
 * close drives the stream to its end in both directions.
 *
 * <p>It keeps track of each direction, because kwik needs it:
 * <ul>
 * <li>kwik gives a stream credit back each time its input is closed once
 * the output is, so stopping to read a stream whose input has already
 * ended would give the hub a second credit. A stream stops reading only
 * while its input is still open.</li>
 * <li>kwik wakes a writer blocked on flow control with an interrupt when
 * the stream is reset, and may leave the thread's interrupt status set.
 * The output clears it, and fails with a plain IOException.</li>
 * <li>Two threads must never read one kwik stream: kwik wakes only the
 * last one when the stream or the connection ends. So drain reads only
 * where nobody else does.</li>
 * </ul>
 *
 * <p>The stream holds its connection until both directions are over, so a
 * retired connection is closed only once it holds nothing (§13.8), and a
 * stream that waits for the hub's end after its own FIN, err or refusal
 * keeps the connection open, for at most DELIVER_WAIT_MS, when the client
 * is closed (§13.5, "Delivering a reason").
 */
final class QStream implements Transport.Stream {
    /** How long an end keeps a stream after its FIN, err, end or refusal, for the peer to end its direction. */
    static final long DELIVER_WAIT_MS = 3000;

    final QuicStream s;
    private final QuicTransport.QConn qc; // null in tests
    private final Runnable release; // the stream's hold on its connection
    private final InputStream in;
    private final OutputStream out;
    private final AtomicBoolean finned = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile boolean outputEnded; // FIN or RESET_STREAM sent
    private volatile boolean inputEnded; // read to its end, failed, or STOP_SENDING sent
    private volatile boolean sawEnd; // the input returned -1
    private final AtomicBoolean lingering = new AtomicBoolean();
    private final AtomicBoolean done = new AtomicBoolean();
    private volatile ScheduledFuture<?> stopTimer;

    QStream(QuicStream s) {
        this(s, null);
    }

    QStream(QuicStream s, QuicTransport.QConn qc) {
        this.s = s;
        this.qc = qc;
        this.release = qc == null ? () -> {} : qc.hold();
        this.in = new In(s.getInputStream());
        this.out = new Out(s.getOutputStream());
    }

    @Override
    public InputStream input() {
        return in;
    }

    @Override
    public OutputStream output() {
        return out;
    }

    /** Whether the input has ended: read to its FIN, reset, or stopped. */
    boolean inputEnded() {
        return inputEnded;
    }

    @Override
    public void finish() throws IOException {
        if (finned.compareAndSet(false, true)) {
            try {
                s.getOutputStream().close();
            } finally {
                outputEnded = true;
                maybeDone();
            }
        }
    }

    /** FIN, never throwing: the stream may be reset already. */
    void finishQuietly() {
        try {
            finish();
        } catch (IOException | RuntimeException ignored) {
            // reset already
        }
    }

    @Override
    public void cancel() {
        reset(Wire.CODE_CANCELLED);
    }

    @Override
    public void broken() {
        reset(Wire.CODE_PROTOCOL);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (finned.get()) {
            linger(); // the peer has a while to end its direction; then stop reading
        } else {
            reset(Wire.CODE_CANCELLED);
        }
    }

    /** Ends both directions at once with code: RESET_STREAM and STOP_SENDING (§13.5). */
    void reset(long code) {
        closed.set(true);
        resetOutput(code);
        stopReading(code);
    }

    /** RESET_STREAM: ends this side's direction, discarding what was not sent. */
    void resetOutput(long code) {
        outputEnded = true;
        try {
            s.resetStream(code);
        } catch (RuntimeException ignored) {
            // ended already
        }
        maybeDone();
    }

    /** STOP_SENDING, unless the input has ended already: kwik would give the hub a second stream credit. */
    void stopReading(long code) {
        if (!inputEnded) {
            inputEnded = true;
            try {
                s.abortReading(code);
            } catch (RuntimeException ignored) {
                // ended already
            }
        }
        inputDone();
    }

    /**
     * Waits for the peer to end its direction, for at most DELIVER_WAIT_MS,
     * then stops reading. Someone must be reading the stream meanwhile.
     */
    private void linger() {
        closed.set(true);
        if (inputEnded) {
            maybeDone();
            return;
        }
        if (lingering.compareAndSet(false, true) && qc != null) {
            qc.lingers(1);
        }
        stopTimer = Bg.after(DELIVER_WAIT_MS, () -> stopReading(Wire.CODE_CANCELLED));
        if (inputEnded) { // ended meanwhile: no need to stop it
            stopTimer.cancel(false);
            maybeDone();
        }
    }

    /**
     * Ends a stream on which only messages were sent: FIN, then reads and
     * discards what comes until the peer ends its direction, for at most
     * DELIVER_WAIT_MS, and stops reading. Only where nobody else reads.
     */
    void finishAndDrain() {
        finishQuietly();
        drain();
    }

    /**
     * Ends a refused request (§13.5): RESET_STREAM ("refused") for this
     * direction, and reads the hub's to its FIN, for at most DELIVER_WAIT_MS.
     */
    void refusedAndDrain() {
        resetOutput(Wire.CODE_REFUSED);
        drain();
    }

    private void drain() {
        linger();
        if (inputEnded) {
            return;
        }
        Bg.go(() -> {
            byte[] buf = new byte[8192];
            try {
                while (in.read(buf) >= 0) {
                    // discarded
                }
            } catch (IOException ignored) {
                // reset, or stopped
            }
        });
    }

    private void inputDone() {
        inputEnded = true;
        ScheduledFuture<?> t = stopTimer;
        if (t != null) {
            t.cancel(false);
        }
        maybeDone();
    }

    /** Both directions are over: the stream no longer holds its connection. */
    private void maybeDone() {
        if (outputEnded && inputEnded && done.compareAndSet(false, true)) {
            if (lingering.get() && qc != null) {
                qc.lingers(-1);
            }
            release.run();
        }
    }

    /** Whether kwik woke a writer because the stream or the connection ended, not someone's interrupt. */
    private boolean wokenByKwik(InterruptedIOException e) {
        String m = String.valueOf(e.getMessage());
        return m.contains("reset") || m.contains("closed") || outputEnded || (qc != null && !qc.alive());
    }

    /** The input, which records its end. */
    private final class In extends InputStream {
        private final InputStream k;

        In(InputStream k) {
            this.k = k;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n;
            do {
                n = read(one, 0, 1);
            } while (n == 0);
            return n < 0 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            if (sawEnd) {
                return -1; // reading again at the end would close kwik's input a second time
            }
            int n;
            try {
                n = k.read(b, off, len);
            } catch (IOException e) {
                inputDone();
                throw e;
            } catch (RuntimeException e) {
                inputDone();
                throw new IOException(e.getMessage(), e);
            }
            if (n < 0) {
                sawEnd = true;
                inputDone();
            }
            return n;
        }

        @Override
        public int available() throws IOException {
            return k.available();
        }
    }

    /** The output, which turns kwik's wake-up interrupt into a plain IOException. */
    private final class Out extends OutputStream {
        private final OutputStream k;

        Out(OutputStream k) {
            this.k = k;
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                k.write(b, off, len);
            } catch (InterruptedIOException e) {
                throw writeFailed(e);
            }
        }

        @Override
        public void flush() throws IOException {
            try {
                k.flush();
            } catch (InterruptedIOException e) {
                throw writeFailed(e);
            }
        }

        @Override
        public void close() throws IOException {
            finish();
        }

        private IOException writeFailed(InterruptedIOException e) {
            if (!wokenByKwik(e)) {
                return e; // the caller's own interrupt
            }
            // kwik interrupted this thread only to wake it; the interrupt is not the caller's
            Thread.interrupted();
            return new IOException(String.valueOf(e.getMessage()), e);
        }
    }
}
