package io.github.wushilin.pfrelayquic;

import io.github.wushilin.pfrelay.Client;

/**
 * The Java SDK for the pf-simple relay hub over QUIC: tunnel protocol 3
 * (docs/PROTOCOL.md §13).
 *
 * <p>It gives the same {@link Client} as pfrelay, with the same API: serve a
 * tunnel ({@link Client#listen()}, {@link Client#serve(String)}) or connect
 * through one ({@link Client#dial()}, {@link Client#check()},
 * {@link Client#connect(java.net.ServerSocket)}). Only the way to the hub
 * differs. The client discovers the hub's QUIC listener over the hub's
 * HTTPS endpoint, pins its certificate by the fingerprint that endpoint
 * announced, and carries each request on a stream of one QUIC connection.
 * A QUIC side works with a WebSocket side through the same hub, in either
 * role.
 *
 * <pre>{@code
 * Client client = QuicClient.builder()        // instead of Client.builder()
 *         .server("https://hub.example.com")
 *         .word("k3f9-x2mq-7hpa")
 *         .build();
 * }</pre>
 *
 * <p>There is no fallback: where UDP is blocked, this fails to connect, and
 * pfrelay (WebSocket) is the one to use. Call {@link Client#close()} at the
 * end of the run to close the QUIC connection.
 */
public final class QuicClient {
    /** This SDK's version. */
    public static final String VERSION = "0.16.0";
    /** What a client calls itself in the hub's log and console unless told otherwise. */
    public static final String DEFAULT_AGENT = "pfrelay-quic-java " + VERSION;
    /**
     * The tunnel protocol this SDK speaks: protocol 3, which exists only
     * over QUIC. It works with clients of protocols 0 to 2 (WebSocket)
     * through the hub, which bridges the two.
     */
    public static final int PROTO = Wire.PROTO;

    private QuicClient() {}

    /**
     * A builder for a {@link Client} that reaches the hub over QUIC. Its
     * settings are pfrelay's: {@code sslContext} and {@code caFile} verify
     * the hub's HTTPS endpoint, where the QUIC listener is discovered. The
     * protocol settings of WebSocket ({@code maxProto}, {@code noReuse},
     * {@code maxIdleLegs}) do not apply. Build one client per builder.
     */
    public static Client.Builder builder() {
        return Client.builder().transport(new QuicTransport()).agent(DEFAULT_AGENT);
    }
}
