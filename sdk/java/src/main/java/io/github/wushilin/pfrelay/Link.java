package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.net.SocketException;

/**
 * What a {@link Conn} carries its frames on: a WebSocket (docs/PROTOCOL.md
 * §8), or a stream of another transport in that transport's encoding
 * ({@link Framed}, docs/PROTOCOL.md §13.5). Either way the Conn sees the
 * same frames: binary data, the text frames "eof" and "err:why", and a
 * close.
 */
interface Link {
    /** How long the peer may stay silent; 0 means no limit. */
    void setReadTimeout(int ms) throws SocketException;

    /** How long one frame write may take before the link is cut; 0 means no limit. */
    void setWriteTimeout(long ms);

    void writeFrame(int op, byte[] p) throws IOException;

    void writeFrame(int op, byte[] p, int off, int len) throws IOException;

    /** Writes a frame unless another write is in progress; returns whether it wrote. */
    boolean tryWriteFrame(int op, byte[] p) throws IOException;

    /** From now on the link is cut after a short while, whatever is still writing or waiting. */
    void beginClose();

    /** Cuts the link at once; whatever blocks on it fails. */
    void abort();

    WebSocket.Frame readHeader() throws IOException;

    int readBody(WebSocket.Frame f, byte[] p, int off, int len) throws IOException;

    byte[] readPayload(WebSocket.Frame f, int max) throws IOException;

    /**
     * Whether this is a stream of a transport that keeps itself alive
     * (QUIC): no pings, and no read timeout, on the stream.
     */
    default boolean framed() {
        return false;
    }

    /**
     * The far end dropped the connection with err: on a framed link, end
     * this side's direction at once (docs/PROTOCOL.md §13.5).
     */
    default void peerFailed() {}
}
