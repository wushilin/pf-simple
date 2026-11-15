package io.github.wushilin.pfrelayquic;

import io.github.wushilin.pfrelay.Transport;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import tech.kwik.core.QuicStream;

/**
 * A QUIC stream after its request and answer, for the Client's frames
 * (docs/PROTOCOL.md §13.5): finish sends FIN, and close drives the stream
 * to its end in both directions.
 */
final class QStream implements Transport.Stream {
    /** How long an end keeps a stream after its FIN, err, end or refusal, for the peer to end its direction. */
    static final long DELIVER_WAIT_MS = 3000;

    private final QuicStream s;
    private final AtomicBoolean finned = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();

    QStream(QuicStream s) {
        this.s = s;
    }

    @Override
    public InputStream input() {
        return s.getInputStream();
    }

    @Override
    public OutputStream output() {
        return s.getOutputStream();
    }

    @Override
    public void finish() throws IOException {
        if (finned.compareAndSet(false, true)) {
            s.getOutputStream().close();
        }
    }

    @Override
    public void cancel() {
        closed.set(true);
        reset(s, Wire.CODE_CANCELLED);
    }

    @Override
    public void broken() {
        closed.set(true);
        reset(s, Wire.CODE_PROTOCOL);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (finned.get()) {
            // the peer has a while to end its direction; then stop reading
            Bg.after(DELIVER_WAIT_MS, () -> s.abortReading(Wire.CODE_CANCELLED));
        } else {
            reset(s, Wire.CODE_CANCELLED);
        }
    }

    /** Ends both directions at once with code: RESET_STREAM and STOP_SENDING (§13.5). */
    static void reset(QuicStream s, long code) {
        try {
            s.resetStream(code);
        } catch (RuntimeException ignored) {
            // ended already
        }
        try {
            s.abortReading(code);
        } catch (RuntimeException ignored) {
            // ended already
        }
    }

    /**
     * Ends a stream on which only messages were sent: FIN, then reads and
     * discards what comes until the peer ends its direction, for at most
     * DELIVER_WAIT_MS, and stops reading.
     */
    static void finishAndDrain(QuicStream s) {
        try {
            s.getOutputStream().close();
        } catch (IOException | RuntimeException ignored) {
            // reset already
        }
        drain(s);
    }

    /** Reads and discards until the peer's direction ends, for at most DELIVER_WAIT_MS; then stops reading. */
    static void drain(QuicStream s) {
        Bg.go(() -> {
            var stop = Bg.after(DELIVER_WAIT_MS, () -> s.abortReading(Wire.CODE_CANCELLED));
            byte[] buf = new byte[8192];
            try {
                InputStream in = s.getInputStream();
                while (in.read(buf) >= 0) {
                    // discarded
                }
            } catch (IOException | RuntimeException ignored) {
                // reset, or stopped
            }
            stop.cancel(false);
        });
    }
}
