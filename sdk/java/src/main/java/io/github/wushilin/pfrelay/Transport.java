package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * A way to reach the hub other than WebSocket, for SDKs built on this one:
 * pfrelay-quic plugs its QUIC transport (docs/PROTOCOL.md §13) in here
 * with {@link Client.Builder#transport}. The {@link Client} keeps
 * everything else (listeners, forwarders, retries, reasons, events, stats,
 * drop, watch), so a program behaves the same on either transport.
 *
 * <p>Applications do not implement this. It is a service-provider
 * interface: it may change with the transports that use it.
 *
 * <p>Refusals come back as {@link StatusException} (with
 * {@link AccessDeniedException} for 403), as over WebSocket.
 */
public interface Transport {
    /** What the transport is called in the log, such as "QUIC". */
    String name();

    /** Registers the tunnel, returning once it is registered. */
    Registration register(Params p, String target) throws IOException;

    /** Opens one connection through the tunnel. */
    Dialed connect(Params p) throws IOException;

    /** Asks whether the tunnel can be reached; returns normally if so. */
    void check(Params p) throws IOException;

    /** Releases what the transport keeps between requests, such as a QUIC connection. */
    void close();

    /** A connection opened by {@link #connect}: its stream, and the hub's id for it. */
    record Dialed(Stream stream, String id) {}

    /** One registration, until it ends. */
    interface Registration {
        /**
         * Waits for the hub's next request for a connection.
         *
         * @throws IOException why the registration ended
         */
        Open next() throws IOException;

        /** Ends the registration; a {@link #next} that waits throws. */
        void close();
    }

    /** The hub asking for one connection. */
    interface Open {
        /** The hub's id for the connection. */
        String id();

        /** Takes the connection: its stream. */
        Stream accept() throws IOException;

        /** Tells the hub why this side cannot carry it. */
        void refuse(String reason);
    }

    /**
     * One stream of the transport after its request and answer, in the
     * transport's frame encoding (docs/PROTOCOL.md §13.5): what the Client
     * turns into a {@link Conn}.
     */
    interface Stream {
        InputStream input();

        OutputStream output();

        /** Ends this side's direction cleanly: QUIC's FIN. */
        void finish() throws IOException;

        /** Ends both directions at once, giving up on the stream (QUIC: reset, "cancelled"). */
        void cancel();

        /** Ends both directions at once because the peer broke the protocol (QUIC: reset, "protocol"). */
        void broken();

        /**
         * Ends what is left. After {@link #finish}, the peer has a short
         * while to end its own direction, so that what was sent last is
         * not lost; otherwise this is {@link #cancel}.
         */
        void close();
    }

    /** An answer of the hub's HTTPS endpoint. */
    record HttpAnswer(int status, Map<String, String> headers, byte[] body) {
        /** The {@code error} of a JSON body, or the body itself, cut short. */
        public String errorText() {
            return Http.errorText(body);
        }

        public String bodyText() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    /** What a transport needs of the Client, made for each request. */
    final class Params {
        private final Client client;
        private final Canceller canceller;

        Params(Client client, Canceller canceller) {
            this.client = client;
            this.canceller = canceller;
        }

        /** The hub's address with its prefix, as https://host[:port]&lt;prefix&gt;, such as https://host/pf. */
        public String server() {
            return client.server();
        }

        /**
         * The request path of a tunnel endpoint under the hub's prefix, for
         * {@link #get}: {@code <prefix>/api/tunnel/<endpoint>}, such as
         * {@code /pf/api/tunnel/quic} (docs/PROTOCOL.md §2).
         */
        public String apiPath(String endpoint) {
            return client.apiPath(endpoint);
        }

        public String word() {
            return client.word();
        }

        /** The serve token; empty to serve anonymously. */
        public String serveToken() {
            return client.serveToken();
        }

        /** The client token; empty if the tunnel has none. */
        public String clientToken() {
            return client.clientToken();
        }

        /** The client token's SHA-256 in hex, as serve registers it; empty without one. */
        public String clientTokenSha256() {
            String t = client.clientToken();
            return t.isEmpty() ? "" : Client.sha256Hex(t);
        }

        /** The tunnel's name, as the console shows it. */
        public String name() {
            return client.name();
        }

        /** What this program calls itself, for the hub's log. */
        public String agent() {
            return client.agent();
        }

        /** Says something in the Client's log. */
        public void log(String msg) {
            client.log(msg);
        }

        /**
         * A GET of path (made with {@link #apiPath}) on the hub's HTTPS
         * endpoint, verified as the Client's own requests are. Any answer
         * comes back; only a failure to get one throws.
         */
        public HttpAnswer get(String path, Map<String, String> headers) throws IOException {
            Map<String, String> h = Http.headers();
            h.putAll(headers);
            Http.Response r = client.httpGet(path, h);
            return new HttpAnswer(r.status, r.headers, r.body);
        }

        /**
         * Runs cancel when whoever made this request (a listener, a watcher)
         * closes, at once if it has; closing the result forgets it.
         */
        public AutoCloseable whenCancelled(Runnable cancel) {
            if (canceller == null) {
                return () -> {};
            }
            return canceller.hook(cancel);
        }
    }
}
