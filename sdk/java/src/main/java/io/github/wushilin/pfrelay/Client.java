package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;

/**
 * Talks to one relay hub about one tunnel (one word). It can serve the
 * tunnel ({@link #listen()}) or connect through it ({@link #dial()},
 * {@link #check()}). Build one with {@link #builder()}; a Client is safe for
 * concurrent use.
 *
 * <p>The protocol is described in docs/PROTOCOL.md.
 */
public final class Client {
    /** This SDK's version. */
    public static final String VERSION = "0.1.0";
    /** What a Client calls itself in the hub's log and console unless told otherwise. */
    public static final String DEFAULT_AGENT = "pfrelay-java " + VERSION;
    /** The target a serving side names when it offers stdin/stdout. */
    public static final String STDIO_TARGET = "stdio";

    static final String PATH = "/pf/api/tunnel/";
    static final String H_WORD = "X-PF-Tunnel-Word";
    static final String H_SERVE = "X-PF-Serve-Token";
    static final String H_CONN = "X-PF-Tunnel-Conn";
    static final String H_NAME = "X-PF-Tunnel-Name";
    static final String H_TARGET = "X-PF-Tunnel-Target";
    static final String H_ERROR = "X-PF-Tunnel-Error";
    static final String H_CLIENT_HASH = "X-PF-Client-Token-SHA256";
    static final String H_CLIENT_TOKEN = "X-PF-Client-Token";
    static final String H_VERSION = "X-PF-Version";

    // Retry timing (docs/PROTOCOL.md §9); package-private so tests can shorten them.
    static volatile long retryMinMs = 1000;
    static volatile long retryMaxMs = 30_000;
    static volatile long settledMs = 60_000;
    static volatile long controlPingMs = 20_000;
    static volatile int controlSilenceMs = 60_000;
    static final long CONTROL_WRITE_TIMEOUT_MS = 10_000;
    static final int MAX_CONTROL_FRAME = 4096;

    private final Http.Target target;
    private final String base;
    private final String word;
    private final SSLContext ssl;
    private final String serveToken;
    private final String clientToken;
    private final String name;
    private final String tunnelTarget;
    private final String agent;
    private final Consumer<String> logger;
    final Registry registry = new Registry();

    private Client(Builder b) {
        this.base = normalizeBase(b.server);
        URI u = URI.create(base);
        String host = u.getHost();
        int port = u.getPort() < 0 ? 443 : u.getPort();
        String bare = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        this.target = new Http.Target(bare, port, u.getRawAuthority());
        this.word = b.word == null || b.word.isEmpty() ? null : Words.normalize(b.word);
        this.serveToken = b.serveToken == null ? "" : b.serveToken;
        if (!serveToken.isEmpty()) {
            checkSecret("serve token", serveToken, 32);
        }
        this.clientToken = b.clientToken == null ? "" : b.clientToken;
        if (!clientToken.isEmpty()) {
            checkSecret("client token", clientToken, 8);
        }
        this.name = b.name == null ? null : checkName(b.name);
        this.tunnelTarget = b.target == null || b.target.isEmpty() ? "listener" : b.target;
        this.agent = b.agent == null || b.agent.isBlank() ? DEFAULT_AGENT : b.agent;
        this.logger = b.logger;
        if (b.sslContext != null) {
            this.ssl = b.sslContext;
        } else if (b.caFile != null) {
            try {
                this.ssl = Tls.trusting(b.caFile);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        } else {
            try {
                this.ssl = SSLContext.getDefault();
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** A builder for a Client. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builds a {@link Client}; {@link #build()} checks the values (docs/PROTOCOL.md §3). */
    public static final class Builder {
        private String server;
        private String word;
        private SSLContext sslContext;
        private Path caFile;
        private String serveToken;
        private String clientToken;
        private String name;
        private String target;
        private String agent;
        private Consumer<String> logger;

        private Builder() {}

        /** The hub: {@code https://host[:port]}, optionally followed by {@code /} or {@code /pf}. */
        public Builder server(String url) {
            this.server = url;
            return this;
        }

        /** The tunnel's word. Only {@link Client#probe()} works without one. */
        public Builder word(String word) {
            this.word = word;
            return this;
        }

        /** The TLS settings to verify the hub with. Default: the JDK's trusted CAs. */
        public Builder sslContext(SSLContext ctx) {
            this.sslContext = ctx;
            return this;
        }

        /** Trust the certificates in this PEM file (the hub's own, or its CA) instead of the JDK's. */
        public Builder caFile(Path pem) {
            this.caFile = pem;
            return this;
        }

        /** A serve token of the hub, for serving and for {@link Client#probe()}. Without one, serving is anonymous. */
        public Builder serveToken(String token) {
            this.serveToken = token;
            return this;
        }

        /** A client token: serving registers its hash, connecting sends it. */
        public Builder clientToken(String token) {
            this.clientToken = token;
            return this;
        }

        /** What the hub's console calls the tunnel; needed to serve. */
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        /** What the hub's console says the tunnel leads to, such as {@code localhost:22}. Default "listener". */
        public Builder target(String target) {
            this.target = target;
            return this;
        }

        /** What this program calls itself in the hub's log, such as "myapp 1.2". Nothing is decided from it. */
        public Builder agent(String agent) {
            this.agent = agent;
            return this;
        }

        /** Receives what the client has to say about registrations, retries and connections. Default: nothing. */
        public Builder logger(Consumer<String> logger) {
            this.logger = logger;
            return this;
        }

        /**
         * Checks the values and makes the Client.
         *
         * @throws IllegalArgumentException for a bad URL, word, token or name
         * @throws UncheckedIOException     if the CA file cannot be read
         */
        public Client build() {
            if (server == null) {
                throw new IllegalArgumentException("the server URL is missing");
            }
            return new Client(this);
        }
    }

    // ---------- values ----------

    /** Accepts the hub's address with or without the console's /pf path, and insists on https. */
    static String normalizeBase(String raw) {
        URI u;
        try {
            u = new URI(raw.strip());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("invalid server URL \"" + raw + "\": use https://host[:port]/");
        }
        if (u.getHost() == null || u.getRawAuthority() == null) {
            throw new IllegalArgumentException("invalid server URL \"" + raw + "\": use https://host[:port]/");
        }
        if (!"https".equalsIgnoreCase(u.getScheme())) {
            throw new IllegalArgumentException("invalid server URL \"" + raw + "\": only https:// is supported");
        }
        String p = u.getRawPath() == null ? "" : u.getRawPath();
        if (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        if (!p.isEmpty() && !p.equals("/pf") || u.getRawQuery() != null || u.getRawFragment() != null
                || u.getRawUserInfo() != null) {
            throw new IllegalArgumentException("invalid server URL \"" + raw
                    + "\": give the server's address only, like https://" + u.getRawAuthority() + "/");
        }
        return "https://" + u.getRawAuthority().toLowerCase(Locale.ROOT);
    }

    /** Serve tokens are 32 to 128, client tokens 8 to 128, printable ASCII characters without spaces. */
    static void checkSecret(String what, String s, int min) {
        if (s.length() < min) {
            throw new IllegalArgumentException("the " + what + " must be at least " + min
                    + " characters long (got " + s.length() + ")");
        }
        if (s.length() > 128) {
            throw new IllegalArgumentException("the " + what + " must be at most 128 characters long");
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= ' ' || c > '~') {
                throw new IllegalArgumentException("the " + what
                        + " may only use printable ASCII characters, without spaces");
            }
        }
    }

    /** A tunnel name is 1 to 64 characters after trimming, with no control characters. */
    static String checkName(String name) {
        String n = name.strip();
        int count = n.codePointCount(0, n.length());
        if (count == 0) {
            throw new IllegalArgumentException("give the tunnel a name");
        }
        if (count > 64) {
            throw new IllegalArgumentException("the tunnel name is longer than 64 characters");
        }
        if (n.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("the tunnel name may not contain control characters");
        }
        return n;
    }

    static String sha256Hex(String s) {
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder(64);
            for (byte x : sum) {
                b.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
            }
            return b.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The word, or an error if this Client was made without one. */
    private String requireWord() {
        if (word == null) {
            throw new IllegalStateException("this client was made without a word");
        }
        return word;
    }

    /** The hub's address, as https://host[:port]. */
    public String server() {
        return base;
    }

    /** The word, lower-cased; null if none was given. */
    public String word() {
        return word;
    }

    // ---------- protocol negotiation (docs/PROTOCOL.md §5) ----------

    /** What a request to endpoint depends on beyond protocol 0. */
    List<Feature> needs(String endpoint) {
        List<Feature> out = new ArrayList<>(2);
        switch (endpoint) {
            case "serve":
                if (!clientToken.isEmpty()) {
                    out.add(Feature.CLIENT_TOKEN);
                }
                if (serveToken.isEmpty()) {
                    out.add(Feature.ANONYMOUS_SERVE);
                }
                break;
            case "connect":
            case "check":
                if (!clientToken.isEmpty()) {
                    out.add(Feature.CLIENT_TOKEN);
                }
                break;
            default:
                break;
        }
        return out;
    }

    /** The protocol range a request to endpoint offers: from its newest feature to the highest spoken. */
    String offer(String endpoint) {
        int min = Proto.MIN;
        for (Feature f : needs(endpoint)) {
            min = Math.max(min, f.proto());
        }
        return Proto.range(min, Proto.MAX);
    }

    /**
     * Checks an answer to endpoint: a hub from before protocols were
     * negotiated ignores what it does not know, so it is for this side to
     * refuse when the request depends on something that hub would not do.
     */
    void answered(String endpoint, Map<String, String> headers) throws ProtoException {
        int proto = Proto.serverProto(headers);
        for (Feature f : needs(endpoint)) {
            if (proto < f.proto()) {
                throw new ProtoException(proto, f);
            }
        }
    }

    /** Makes one request, and checks every answer except 404 for the protocol (§5.3). */
    private Http.Response exchange(String endpoint, Map<String, String> h, boolean upgrade) throws IOException {
        h.put(Proto.HEADER, offer(endpoint));
        h.put(H_VERSION, agent);
        Http.Response r = Http.request(target, PATH + endpoint, h, ssl, upgrade);
        if (r.status != 404) {
            try {
                answered(endpoint, r.headers);
            } catch (ProtoException e) {
                if (r.ws != null) {
                    r.ws.abort();
                }
                throw e;
            }
        }
        return r;
    }

    /** Opens a WebSocket at endpoint; any answer but 101 is an exception. */
    WebSocket openWs(String endpoint, Map<String, String> h) throws IOException {
        Http.Response r = exchange(endpoint, h, true);
        if (r.ws == null) {
            throw explain(r.status, r.errorText(), r.headers);
        }
        return r.ws;
    }

    /** Makes a plain GET; anything but 2xx is an exception. */
    private Http.Response get(String endpoint, Map<String, String> h) throws IOException {
        Http.Response r = exchange(endpoint, h, false);
        if (r.status / 100 != 2) {
            throw explain(r.status, r.errorText(), r.headers);
        }
        return r;
    }

    /** Turns the hub's refusals into something to act on (docs/PROTOCOL.md §9). */
    static StatusException explain(int code, String msg, Map<String, String> headers) {
        if (code == 403) {
            return new AccessDeniedException(headers);
        }
        if (code == 404 && msg.isEmpty()) {
            return new StatusException(404, "this server does not accept tunnels (its relay hub is off or not configured)",
                    headers);
        }
        return new StatusException(code, msg, headers);
    }

    Map<String, String> header(String conn) {
        Map<String, String> h = Http.headers();
        h.put(H_WORD, requireWord());
        if (conn != null) {
            h.put(H_CONN, conn);
        }
        return h;
    }

    /** What the connecting side sends: the word, and the client token if there is one. */
    private Map<String, String> connectHeader() {
        Map<String, String> h = header(null);
        if (!clientToken.isEmpty()) {
            h.put(H_CLIENT_TOKEN, clientToken);
        }
        return h;
    }

    // ---------- the connecting side ----------

    /**
     * Opens one connection through the tunnel.
     *
     * <p>The hub answers before the serving side has: if the serving side
     * cannot be reached, or cannot reach its target, the first read throws a
     * {@link RemoteException} saying so.
     *
     * @throws AccessDeniedException nobody serves the word, or the client token is missing or wrong
     * @throws ProtoException        the hub is too old for the client token
     */
    public Conn dial() throws IOException {
        WebSocket ws = openWs("connect", connectHeader());
        String id = ws.header.getOrDefault(H_CONN, "");
        try {
            return new Conn(ws, registry, id, Side.CONNECT);
        } catch (IOException e) {
            ws.abort();
            throw e;
        }
    }

    /**
     * Asks the hub whether someone serves this word (and whether the client
     * token, if one is needed, is right). Returns normally if so.
     *
     * @throws AccessDeniedException otherwise
     * @throws ProtoException        the hub is too old for the client token
     */
    public void check() throws IOException {
        get("check", connectHeader());
    }

    /**
     * Asks the hub for its version and the tunnel protocols it speaks. It
     * needs a valid serve token: without one the hub says nothing about
     * itself.
     *
     * @throws AccessDeniedException a missing or wrong serve token
     * @throws StatusException       404: the hub is older than 0.14.0, or its relay is off
     */
    public ServerInfo probe() throws IOException {
        Map<String, String> h = Http.headers();
        if (!serveToken.isEmpty()) {
            h.put(H_SERVE, serveToken);
        }
        Http.Response r = exchange("version", h, false);
        if (r.status == 404) {
            throw new StatusException(404, "this server does not answer a version probe: it is older than "
                    + "pf-simple 0.14.0, or its relay hub is off", r.headers);
        }
        if (r.status / 100 != 2) {
            throw explain(r.status, r.errorText(), r.headers);
        }
        try {
            Map<String, Object> m = Json.parseObject(new String(r.body, StandardCharsets.UTF_8));
            Object v = m.get("version");
            if (!(v instanceof String) || ((String) v).isEmpty()) {
                throw new IOException("no version");
            }
            return new ServerInfo((String) v, num(m.get("protoMin")), num(m.get("protoMax")),
                    m.get("token") instanceof String ? (String) m.get("token") : "");
        } catch (IOException e) {
            throw new IOException("the server's answer to the version probe is not understood");
        }
    }

    private static int num(Object o) {
        return o instanceof Number ? ((Number) o).intValue() : 0;
    }

    // ---------- the serving side ----------

    /**
     * Registers the tunnel with the hub and returns once it is registered.
     * The listener then keeps itself registered: a lost hub is registered
     * with again, with a growing pause, until it is closed.
     *
     * <p>A refusal that waiting cannot cure is thrown: a wrong serve token
     * ({@link AccessDeniedException}), a word that belongs to another tenant
     * (a {@link StatusException} with the hub's message), a hub too old for
     * what was asked ({@link ProtoException}). Anything else, a hub that
     * cannot be reached included, is retried.
     */
    public Listener listen() throws IOException {
        return listen(null);
    }

    /**
     * {@link #listen()}, waiting at most timeout for the first registration.
     *
     * @throws java.io.InterruptedIOException if it is not registered in time
     */
    public Listener listen(Duration timeout) throws IOException {
        if (name == null) {
            throw new IllegalStateException("give the tunnel a name to serve it (Client.Builder.name)");
        }
        requireWord();
        Listener l = new Listener(this);
        l.start();
        l.awaitRegistered(timeout);
        return l;
    }

    /** The headers of a registration. */
    Map<String, String> serveHeader() {
        Map<String, String> h = header(null);
        h.put(H_TARGET, tunnelTarget);
        if (!serveToken.isEmpty()) {
            h.put(H_SERVE, serveToken);
        }
        if (!clientToken.isEmpty()) {
            h.put(H_CLIENT_HASH, sha256Hex(clientToken));
        }
        h.put(H_NAME, URLEncoder.encode(name, StandardCharsets.UTF_8));
        return h;
    }

    /** Refuses connection id, with a reason the connecting side hears. */
    void refuse(String id, String reason) {
        Map<String, String> h = header(id);
        h.put(H_ERROR, reason);
        try {
            get("accept", h);
        } catch (IOException e) {
            log("connection " + shortId(id) + ": could not tell the server: " + e.getMessage());
        }
    }

    // ---------- bookkeeping ----------

    /** This client's totals, open connections included. */
    public Stats stats() {
        return registry.stats();
    }

    /** This client's open connections, oldest first. */
    public List<ConnInfo> conns() {
        return registry.conns();
    }

    void log(String msg) {
        Consumer<String> l = logger;
        if (l != null) {
            try {
                l.accept(msg);
            } catch (RuntimeException ignored) {
                // a logger's trouble is not the tunnel's
            }
        }
    }

    /** The word as logs show it: enough to tell tunnels apart, not enough to connect. */
    String wordLabel() {
        return word == null ? "-" : word.substring(0, 4) + "-…";
    }

    static String shortId(String id) {
        return id.length() > 8 ? id.substring(0, 8) : id;
    }

    String target() {
        return tunnelTarget;
    }

    String name() {
        return name;
    }
}
