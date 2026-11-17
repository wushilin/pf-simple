package io.github.wushilin.pfrelayquic;

import io.github.wushilin.pfrelay.AccessDeniedException;
import io.github.wushilin.pfrelay.StatusException;
import io.github.wushilin.pfrelay.Transport;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import tech.kwik.core.ConnectionListener;
import tech.kwik.core.ConnectionTerminatedEvent;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.impl.QuicConnectionImpl;

/**
 * Reaches the hub over QUIC (docs/PROTOCOL.md §13): discovery over the
 * hub's HTTPS endpoint, one QUIC connection made again when it is lost,
 * and one stream per request. The Client it is plugged into does the rest.
 */
final class QuicTransport implements Transport {
    /** The discovery endpoint, under the hub's prefix (§13.2). */
    static final String DISCOVERY = "quic";
    static final String H_OP = "X-PF-Tunnel-Op";
    static final String H_WORD = "X-PF-Tunnel-Word";
    static final String H_SERVE = "X-PF-Serve-Token";
    static final String H_CLIENT_TOKEN = "X-PF-Client-Token";
    static final String H_PROTO = "X-PF-Tunnel-Proto";

    static final String NO_QUIC = "this hub does not offer QUIC: it is older than pf-simple 0.16.0, or its relay hub "
            + "is off; upgrade it, or use pf-client (WebSocket)";

    // Timing and sizes (§13.3, §13.4, §13.6).
    static final Duration IDLE_TIMEOUT = Duration.ofSeconds(30);
    /** Keepalive: a PING at least this often, so no 10 seconds pass without one (§13.6). */
    static final long PING_EVERY_MS = 5_000;
    static final long HANDSHAKE_TIMEOUT_MS = 10_000;
    static final long REQUEST_WAIT_MS = 10_000; // an open, or a reg named before its serve's answer
    static final long ANSWER_WAIT_MS = 15_000; // the client's wait for the hub's answer
    static final long WRITE_TIMEOUT_MS = 10_000;
    static final long STREAM_WINDOW = 256 << 10; // at least 64 KiB
    static final long CONN_WINDOW = 16 << 20; // at least 16 MiB, at least 16 times the stream window
    static final int MAX_STREAMS = 1000; // the hub may open this many streams to a serving side
    static final int BACKLOG = 128;

    private static final Object KWIK_BUILD = new Object();

    /** What a full open queue is refused with, as pfrelay says it over WebSocket (§9). */
    static final String REASON_BACKLOG = "the serving side is not accepting connections fast enough";

    private QConn conn; // guarded by this
    private final List<QConn> retired = new ArrayList<>(); // dropped, closed once they hold nothing; guarded by this
    // Held while a connection is made, apart from this, so that close() and
    // requests on a live connection never wait behind a discovery or a handshake.
    private final Object dialing = new Object();

    @Override
    public String name() {
        return "QUIC";
    }

    /**
     * Closes the QUIC connections to the hub (none). Streams that sent an
     * err, a refusal or an unregister FIN get up to DELIVER_WAIT_MS for the
     * hub to end its direction first, as closing a connection drops what is
     * still queued (§13.5, "Delivering a reason").
     */
    @Override
    public void close() {
        List<QConn> all;
        synchronized (this) {
            all = new ArrayList<>(retired);
            if (conn != null) {
                all.add(conn);
            }
            conn = null;
            retired.clear();
        }
        CountDownLatch closed = new CountDownLatch(all.size());
        for (QConn qc : all) {
            Bg.go(() -> {
                try {
                    qc.close(Wire.CODE_NONE, "done");
                } finally {
                    closed.countDown();
                }
            });
        }
        try {
            closed.await(QStream.DELIVER_WAIT_MS + 1000, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ---------- discovery and the connection ----------

    /** Asks the hub's HTTPS endpoint where its QUIC listener is (§13.2), with the run's credentials. */
    Discovery discover(Params p, String op) throws IOException {
        Map<String, String> h = new LinkedHashMap<>();
        h.put(H_OP, op);
        if (op.equals("serve")) {
            if (!p.serveToken().isEmpty()) {
                h.put(H_SERVE, p.serveToken());
            }
        } else {
            h.put(H_WORD, p.word());
            if (!p.clientToken().isEmpty()) {
                h.put(H_CLIENT_TOKEN, p.clientToken());
            }
        }
        HttpAnswer a = p.get(p.apiPath(DISCOVERY), h);
        if (a.status() == 404) { // a hub without QUIC does not know the endpoint
            throw new StatusException(404, NO_QUIC, a.headers());
        }
        if (a.status() == 403) {
            throw new AccessDeniedException(a.headers());
        }
        if (a.status() != 200) {
            throw new StatusException(a.status(), a.errorText(), a.headers());
        }
        return Discovery.parse(a.bodyText());
    }

    /**
     * The QUIC connection to the hub, made if there is none: discovery, then
     * a handshake that pins the certificate, with one more discovery after
     * a mismatch (§13.3).
     */
    QConn get(Params p, String op) throws IOException {
        QConn qc = current();
        if (qc != null) {
            return qc;
        }
        synchronized (dialing) {
            qc = current(); // made meanwhile by another caller
            if (qc != null) {
                return qc;
            }
            for (int attempt = 0;; attempt++) {
                Discovery d = discover(p, op);
                Pin pin = new Pin(d.fingerprints());
                try {
                    qc = dial(d, pin);
                    synchronized (this) {
                        conn = qc;
                    }
                    return qc;
                } catch (IOException e) {
                    if (!pin.mismatched()) {
                        throw dialError(e);
                    }
                    if (attempt >= 1) {
                        throw new IOException(Pin.MISMATCH);
                    }
                    p.log("the hub's QUIC certificate does not match its announcement; discovering again");
                }
            }
        }
    }

    /** The connection to use, if there is a live one; a dead one is retired. */
    QConn current() {
        QConn dead;
        synchronized (this) {
            if (conn == null || conn.alive()) {
                return conn;
            }
            dead = conn;
        }
        drop(dead);
        return null;
    }

    QConn dial(Discovery d, Pin pin) throws IOException {
        QuicClientConnection c;
        synchronized (KWIK_BUILD) {
            // The name is not checked (§13.3); kwik warns on stdout when told
            // so, and stdout may be the application's. The pin replaces it.
            String key = "tech.kwik.core.no-security-warnings";
            String before = System.getProperty(key);
            System.setProperty(key, "true");
            try {
                QuicClientConnection.Builder b = QuicClientConnection.newBuilder()
                        .version(QuicConnection.QuicVersion.V1)
                        .host(d.host())
                        .port(d.port())
                        .applicationProtocol(Wire.ALPN)
                        .connectTimeout(Duration.ofMillis(HANDSHAKE_TIMEOUT_MS))
                        .maxIdleTimeout(IDLE_TIMEOUT)
                        // the connection window is ten times this; streams get theirs below
                        .defaultStreamReceiveBufferSize((CONN_WINDOW + 9) / 10)
                        .maxOpenPeerInitiatedBidirectionalStreams(MAX_STREAMS)
                        .maxOpenPeerInitiatedUnidirectionalStreams(0)
                        .customTrustManager(pin)
                        .noServerHostnameVerification();
                c = b.build();
            } finally {
                if (before == null) {
                    System.clearProperty(key);
                } else {
                    System.setProperty(key, before);
                }
            }
        }
        c.setDefaultBidirectionalStreamReceiveBufferSize(STREAM_WINDOW);
        QConn qc = new QConn(c);
        c.setPeerInitiatedStreamCallback(s -> Bg.go(() -> qc.opened(s)));
        c.setConnectionListener(new ConnectionListener() {
            @Override
            public void disconnected(ConnectionTerminatedEvent e) {
                qc.lost(describe(e));
            }
        });
        try {
            c.connect();
        } catch (IOException | RuntimeException e) {
            qc.lost("the handshake failed");
            try {
                c.close();
            } catch (RuntimeException ignored) {
                // never connected
            }
            throw e instanceof IOException ? (IOException) e : new IOException(e.getMessage(), e);
        }
        qc.started();
        return qc;
    }

    private static String describe(ConnectionTerminatedEvent e) {
        StringBuilder b = new StringBuilder();
        switch (e.closeReason()) {
            case IdleTimeout:
                b.append("the QUIC connection was silent for ").append(IDLE_TIMEOUT.toSeconds()).append("s");
                break;
            case ConnectionLost:
            case StatelessReset:
                b.append("the QUIC connection was lost");
                break;
            default:
                b.append(e.closedByPeer() ? "the hub closed the QUIC connection" : "the QUIC connection was closed");
        }
        if (e.hasApplicationError()) {
            b.append(" (").append(codeName(e.applicationErrorCode())).append(")");
        }
        return b.toString();
    }

    static String codeName(Long code) {
        if (code == null) {
            return "broken";
        }
        switch (code.intValue()) {
            case 0: return "none";
            case 2: return "refused";
            case 3: return "protocol";
            case 4: return "request-timeout";
            case 5: return "cancelled";
            case 6: return "going-away";
            case 7: return "limit";
            default: return "broken";
        }
    }

    /** Words a failure to reach the QUIC listener. */
    static IOException dialError(IOException e) {
        String m = String.valueOf(e.getMessage());
        String lower = m.toLowerCase(java.util.Locale.ROOT);
        // kwik: "Handshake error: tech.kwik.core.impl.VersionNegotiationFailure"
        if (lower.contains("versionnegotiation") || lower.contains("version negotiation")) {
            return new IOException(NO_QUIC_V1);
        }
        // A refused handshake (§13.7): CONNECTION_REFUSED, transport error 2.
        // kwik: "Handshake error: Server closed connection: transport error 2: "
        if (REFUSED.matcher(lower).find() || lower.contains("connection_refused")) {
            return new StatusException(429, "the hub refused the QUIC connection; trying again later");
        }
        return new IOException("cannot reach the hub over QUIC (UDP may be blocked on the way; pf-client over "
                + "WebSocket works where QUIC does not): " + m, e);
    }

    static final String NO_QUIC_V1 = "the hub's QUIC listener does not speak QUIC version 1";
    private static final Pattern REFUSED = Pattern.compile("transport error 2(?![0-9])");

    /**
     * Forgets qc as the connection to use, if it still is, and closes it
     * (none) once it holds no stream and no registration (§13.8).
     */
    void drop(QConn qc) {
        synchronized (this) {
            if (conn == qc) {
                conn = null;
            }
            retired.removeIf(r -> r == qc || !r.alive());
            retired.add(qc);
        }
        qc.retire();
    }

    // ---------- requests ----------

    /** A request's stream and the hub's answer to it. */
    private record Answered(QStream q, Map<String, Object> answer) {}

    /**
     * Opens a stream on qc. kwik turns an interrupt of the caller into a
     * RuntimeException: on a live connection that is the caller's
     * interrupt, not a lost connection.
     */
    QStream open(QConn qc) throws IOException {
        QuicStream s;
        try {
            s = qc.c.createStream(true);
        } catch (IOException | RuntimeException e) {
            if (qc.alive() && e instanceof RuntimeException) {
                Thread.currentThread().interrupt();
                InterruptedIOException ie = new InterruptedIOException("interrupted");
                ie.initCause(e);
                throw ie;
            }
            drop(qc);
            String why = qc.why().isEmpty() ? String.valueOf(e.getMessage()) : qc.why();
            throw new IOException("the QUIC connection to the hub was lost (" + why + ")", e);
        }
        return new QStream(s, qc);
    }

    /**
     * Opens a stream on qc, sends the request, and reads the hub's answer.
     * A refusal is thrown, after the stream is ended (§13.5).
     */
    private Answered request(Params p, Wire.Obj req, QConn qc) throws IOException {
        req.put("proto", Integer.toString(Wire.PROTO)).put("version", p.agent()).put("word", p.word());
        byte[] msg = Wire.encode(req.toString()); // too long: refused before anything is sent
        QStream q = open(qc);
        AtomicBoolean cancelled = new AtomicBoolean();
        AtomicBoolean timedOut = new AtomicBoolean();
        Map<String, Object> a;
        IOException werr = null;
        AutoCloseable hook = p.whenCancelled(() -> {
            cancelled.set(true);
            q.reset(Wire.CODE_CANCELLED);
        });
        try {
            ScheduledFuture<?> deadline = Bg.after(ANSWER_WAIT_MS, () -> {
                timedOut.set(true);
                q.reset(Wire.CODE_REQUEST_TIMEOUT);
            });
            try {
                try {
                    q.output().write(msg);
                    q.output().flush();
                } catch (IOException e) {
                    // Read the answer all the same: the hub's refusal can
                    // overtake the request, and it says why (§13.5).
                    werr = e;
                }
                a = Wire.read(q.input());
                if (a == null) {
                    throw new Wire.MessageException("the stream ended before the answer");
                }
            } catch (IOException e) {
                q.reset(timedOut.get() ? Wire.CODE_REQUEST_TIMEOUT : Wire.CODE_PROTOCOL);
                if (cancelled.get()) {
                    throw new InterruptedIOException("cancelled");
                }
                if (!qc.alive()) {
                    throw new IOException("the QUIC connection to the hub was lost (" + qc.why() + ")");
                }
                if (timedOut.get()) {
                    throw new IOException("the hub did not answer within " + ANSWER_WAIT_MS / 1000 + "s");
                }
                if (werr != null) {
                    throw new IOException("cannot send the request to the hub: " + werr.getMessage(), werr);
                }
                throw new IOException("the hub did not answer: " + e.getMessage(), e);
            } finally {
                deadline.cancel(false);
            }
        } finally {
            try {
                hook.close();
            } catch (Exception ignored) {
                // forgetting it cannot fail
            }
        }
        // The status first: a refusal, a 426 included, carries the hub's own
        // protocol in proto, and its message says which side to upgrade (§13.4).
        int status = Wire.num(a, "status");
        int proto = Wire.num(a, "proto");
        if (status != 200 && status != 204) {
            // The hub sends FIN and STOP_SENDING: end this direction too (§13.5).
            q.refusedAndDrain();
            if (status == 429 && "connection".equals(Wire.str(a, "scope"))) {
                drop(qc); // the next request opens a new connection (§13.8)
            }
            Map<String, String> hd = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            hd.put(H_PROTO, Integer.toString(proto));
            String err = Wire.str(a, "error");
            if (status == 403) {
                throw new AccessDeniedException(hd);
            }
            if (status == 0) {
                throw new IOException("the hub's answer is not understood");
            }
            throw new StatusException(status, err, hd);
        }
        if (werr != null) {
            q.reset(Wire.CODE_BROKEN);
            throw new IOException("cannot send the request to the hub: " + werr.getMessage(), werr);
        }
        if (proto != Wire.PROTO) {
            q.reset(Wire.CODE_PROTOCOL);
            // final: trying again cannot help, one side must be upgraded
            throw new StatusException(426, "the hub answered in QUIC protocol " + proto + "; this client speaks "
                    + Wire.PROTO);
        }
        return new Answered(q, a);
    }

    @Override
    public void check(Params p) throws IOException {
        Wire.Obj req = new Wire.Obj().put("op", "check").put("clientToken", p.clientToken());
        Answered r = request(p, req, get(p, "connect"));
        r.q.finishAndDrain();
    }

    @Override
    public Dialed connect(Params p) throws IOException {
        Wire.Obj req = new Wire.Obj().put("op", "connect").put("clientToken", p.clientToken());
        Answered r = request(p, req, get(p, "connect"));
        return new Dialed(r.q, Wire.str(r.answer, "conn"));
    }

    @Override
    public Registration register(Params p, String target) throws IOException {
        Wire.Obj req = new Wire.Obj().put("op", "serve").put("serveToken", p.serveToken()).put("name", p.name())
                .put("target", target).put("clientTokenSHA256", p.clientTokenSha256());
        // An open may arrive before the answer (§13.4): the serve is counted
        // on the connection its request goes on, until its registration is there.
        QConn qc = get(p, "serve");
        qc.serving(1);
        Answered r;
        try {
            r = request(p, req, qc);
        } catch (IOException | RuntimeException e) {
            qc.serving(-1);
            throw e;
        }
        String id = Wire.str(r.answer, "reg");
        if (id.isEmpty()) {
            qc.serving(-1);
            r.q.broken();
            throw new IOException("the hub broke the protocol: its answer to serve names no registration");
        }
        Reg reg = new Reg(qc, r.q, id);
        qc.registered(reg);
        Bg.go(reg::watch);
        return reg;
    }

    // ---------- one QUIC connection ----------

    /** One QUIC connection to the hub, and its registrations. */
    static final class QConn {
        final QuicClientConnection c;
        private final Map<String, Reg> regs = new HashMap<>(); // guarded by this
        private int serves; // serve requests not yet answered; guarded by this
        private int held; // streams in use; guarded by this
        private int lingering; // streams waiting for the hub's end of them; guarded by this
        private boolean retired; // no new request goes here; guarded by this
        private boolean closing; // guarded by this
        private volatile boolean dead;
        private volatile String why = "";
        private volatile ScheduledFuture<?> pinger;

        QConn(QuicClientConnection c) {
            this.c = c;
        }

        boolean alive() {
            return !dead && c.isConnected();
        }

        String why() {
            return why;
        }

        /** Starts the keepalive: a PING every PING_EVERY_MS (§13.6). */
        void started() {
            pinger = Bg.every(PING_EVERY_MS, this::ping);
            if (dead) {
                pinger.cancel(false);
            }
        }

        /** One PING; a connection that kwik ended without telling is lost. */
        void ping() {
            if (dead) {
                return;
            }
            if (!c.isConnected()) {
                // kwik ends a connection on a fatal error of its own without an event
                lost("the QUIC connection was lost");
                return;
            }
            try {
                ((QuicConnectionImpl) c).send(new PingFrame(), f -> {}, true);
            } catch (LinkageError e) {
                // kwik on the module path hides its implementation: fall
                // back to its own keepalive, which pings less often
                ScheduledFuture<?> p = pinger;
                if (p != null) {
                    p.cancel(false);
                }
                c.keepAlive(Integer.MAX_VALUE / 2);
            } catch (RuntimeException ignored) {
                // the connection is going
            }
        }

        /**
         * Closes the connection, after giving the streams that wait for the
         * hub's end of them up to DELIVER_WAIT_MS (§13.5).
         */
        void close(long code, String reason) {
            synchronized (this) {
                if (closing) {
                    return;
                }
                closing = true;
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(QStream.DELIVER_WAIT_MS);
                while (lingering > 0 && !dead) {
                    long left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
                    if (left <= 0) {
                        break;
                    }
                    try {
                        wait(left);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            lost("closed");
            try {
                c.close(code, reason);
            } catch (RuntimeException ignored) {
                // gone already
            }
        }

        /** The connection is gone: so are its registrations (§13.6). */
        void lost(String reason) {
            Reg[] all;
            synchronized (this) {
                if (dead) {
                    return;
                }
                dead = true;
                why = reason;
                all = regs.values().toArray(new Reg[0]);
                notifyAll();
            }
            ScheduledFuture<?> p = pinger;
            if (p != null) {
                p.cancel(false);
            }
            for (Reg r : all) {
                r.end(new IOException("the link to the server was lost (" + reason + ")"));
            }
        }

        /** Counts a stream as in use; the result, run once, ends that. */
        Runnable hold() {
            synchronized (this) {
                held++;
            }
            AtomicBoolean once = new AtomicBoolean();
            return () -> {
                if (once.compareAndSet(false, true)) {
                    synchronized (this) {
                        held--;
                    }
                    closeIfIdle();
                }
            };
        }

        /** Counts the streams that wait for the hub's end of them. */
        synchronized void lingers(int d) {
            lingering += d;
            notifyAll();
        }

        /** No new request goes here: the connection is closed once it holds nothing (§13.8). */
        void retire() {
            synchronized (this) {
                retired = true;
            }
            closeIfIdle();
        }

        private void closeIfIdle() {
            synchronized (this) {
                if (!retired || closing || held > 0 || !regs.isEmpty()) {
                    return;
                }
            }
            Bg.go(() -> close(Wire.CODE_NONE, "done"));
        }

        synchronized void serving(int d) {
            serves += d;
            notifyAll();
        }

        /**
         * Adds a registration whose serve was answered, and stops counting
         * the serve, in one step: a find() that waits sees one or the other.
         */
        void registered(Reg r) {
            add(r, 1);
        }

        /** Adds a registration. */
        void add(Reg r) {
            add(r, 0);
        }

        private void add(Reg r, int answered) {
            boolean gone;
            synchronized (this) {
                regs.put(r.id, r);
                serves -= answered;
                notifyAll();
                gone = dead;
            }
            if (gone) {
                Bg.go(() -> r.end(new IOException("the link to the server was lost (" + why + ")")));
            }
        }

        void remove(Reg r) {
            synchronized (this) {
                regs.remove(r.id, r);
                notifyAll();
            }
            closeIfIdle();
        }

        /**
         * The registration reg names. An open can arrive before the answer
         * to its serve, streams not being ordered with one another, so it
         * waits while serves are outstanding, up to REQUEST_WAIT_MS (§13.4).
         */
        synchronized Reg find(String reg) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(REQUEST_WAIT_MS);
            while (true) {
                Reg r = regs.get(reg);
                if (r != null || serves == 0 || dead) {
                    return r;
                }
                long left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
                if (left <= 0) {
                    return null;
                }
                wait(left);
            }
        }

        /** A stream the hub opened: an open for one of this connection's registrations. */
        void opened(QuicStream s) {
            QStream q = new QStream(s, this);
            ScheduledFuture<?> deadline = Bg.after(REQUEST_WAIT_MS, () -> q.reset(Wire.CODE_REQUEST_TIMEOUT));
            Map<String, Object> m;
            try {
                m = Wire.read(q.input());
            } catch (IOException e) {
                deadline.cancel(false);
                q.reset(Wire.CODE_PROTOCOL);
                return;
            }
            if (!deadline.cancel(false)) {
                return; // timed out, and reset
            }
            String id = m == null ? "" : Wire.str(m, "open");
            if (id.isEmpty()) {
                q.reset(Wire.CODE_PROTOCOL);
                return;
            }
            Reg r;
            try {
                r = find(Wire.str(m, "reg"));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                q.reset(Wire.CODE_CANCELLED);
                return;
            }
            OpenImpl o = new OpenImpl(q, id);
            if (r == null) {
                o.refuse(410, "no such registration");
            } else {
                r.deliver(o);
            }
        }
    }

    // ---------- a registration ----------

    /** One registration over QUIC, until its serve stream ends. */
    static final class Reg implements Registration {
        private static final Object END = new Object();

        private final QConn qc;
        private final QStream q;
        final String id;
        private final ArrayBlockingQueue<Object> opens = new ArrayBlockingQueue<>(BACKLOG + 1);
        private volatile IOException why;
        private boolean ended; // guarded by this
        private volatile boolean unregistered;

        Reg(QConn qc, QuicStream s, String id) {
            this(qc, new QStream(s, qc), id);
        }

        Reg(QConn qc, QStream q, String id) {
            this.qc = qc;
            this.q = q;
            this.id = id;
        }

        /**
         * Queues an open for next(), or refuses it: 410 once the
         * registration has ended, 502 with a reason when the queue is full (§9).
         */
        void deliver(OpenImpl o) {
            int refuse;
            synchronized (this) {
                if (ended) {
                    refuse = 410;
                } else if (opens.size() >= BACKLOG) {
                    refuse = 502;
                } else {
                    opens.add(o);
                    return;
                }
            }
            if (refuse == 410) {
                o.refuse(410, "no such registration");
            } else {
                o.refuse(502, REASON_BACKLOG);
            }
        }

        /**
         * Reads the serve stream until it ends: the hub's FIN, a reset, or a
         * lost connection. It is the stream's only reader: after an end
         * message, or this side's unregister, it reads on to the hub's FIN.
         */
        void watch() {
            IOException e = null;
            while (true) {
                Map<String, Object> m;
                try {
                    m = Wire.read(q.input());
                } catch (Wire.MessageException x) {
                    q.broken(); // reset (protocol)
                    if (e == null) {
                        e = unregistered ? new IOException("unregistered")
                                : new IOException("the server broke the protocol on the serve stream (" + x.getMessage()
                                        + ")");
                    }
                    break;
                } catch (IOException x) {
                    if (e == null) {
                        e = unregistered ? new IOException("unregistered")
                                : new IOException("the link to the server was lost ("
                                        + (qc.alive() ? x.getMessage() : qc.why()) + ")");
                    }
                    break;
                }
                if (m == null) { // the hub's FIN: answer with ours
                    if (e == null) {
                        e = unregistered ? new IOException("unregistered")
                                : new IOException("the server ended the registration");
                    }
                    q.finishQuietly();
                    break;
                }
                String end = Wire.str(m, "end");
                if (end.isEmpty() || e != null) {
                    continue; // unknown messages are ignored
                }
                String reason = Wire.ascii(Wire.str(m, "error"), 200);
                if (reason.isEmpty()) {
                    reason = "the server ended the registration";
                }
                if (end.equals(Wire.END_TAKEOVER)) {
                    reason += " (another serving side registered the same word)";
                }
                e = new IOException(reason);
                end(e); // at once; the hub's FIN follows
                q.finishQuietly(); // answer with ours, and read on to the hub's, for a while
                q.close();
            }
            q.close();
            end(e);
        }

        /** Ends the registration once: next() throws e, and queued opens are refused 410 at once (§13.5). */
        void end(IOException e) {
            List<OpenImpl> queued = new ArrayList<>();
            synchronized (this) {
                if (ended) {
                    return;
                }
                ended = true;
                why = e;
                Object o;
                while ((o = opens.poll()) != null) {
                    if (o instanceof OpenImpl) {
                        queued.add((OpenImpl) o);
                    }
                }
                opens.add(END);
            }
            qc.remove(this);
            for (OpenImpl o : queued) {
                Bg.go(() -> o.refuse(410, "no such registration"));
            }
        }

        @Override
        public Open next() throws IOException {
            Object o;
            try {
                o = opens.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted");
            }
            if (o == END) {
                opens.offer(END); // for whoever waits next
                throw why;
            }
            return (Open) o;
        }

        /**
         * Unregisters: FIN on the serve stream (§13.4). watch() reads on to
         * the hub's FIN; DELIVER_WAIT_MS bounds the wait.
         */
        @Override
        public void close() {
            unregistered = true;
            end(new IOException("unregistered"));
            q.finishQuietly();
            q.close();
        }
    }

    // ---------- an open ----------

    /** The hub asking for one connection, on a stream it opened. */
    static final class OpenImpl implements Open {
        private final QStream q;
        private final String id;
        private final AtomicBoolean answered = new AtomicBoolean();

        OpenImpl(QStream q, String id) {
            this.q = q;
            this.id = id;
        }

        @Override
        public String id() {
            return id;
        }

        private void write(Wire.Obj a) throws IOException {
            ScheduledFuture<?> watchdog = Bg.after(WRITE_TIMEOUT_MS, () -> q.reset(Wire.CODE_BROKEN));
            try {
                Wire.write(q.output(), a.toString());
            } finally {
                watchdog.cancel(false);
            }
        }

        /** A refusal: the answer, then FIN, and the hub's FIN read for a while (§13.5). */
        void refuse(int status, String reason) {
            if (!answered.compareAndSet(false, true)) {
                return;
            }
            try {
                write(new Wire.Obj().put("status", status).put("error", reason));
            } catch (IOException ignored) {
                // the stream is gone
            }
            q.finishAndDrain();
        }

        @Override
        public Stream accept() throws IOException {
            if (!answered.compareAndSet(false, true)) {
                throw new IOException("this connection was answered already");
            }
            try {
                write(new Wire.Obj().put("status", 200));
            } catch (IOException e) {
                q.reset(Wire.CODE_BROKEN);
                throw e;
            }
            return q;
        }

        @Override
        public void refuse(String reason) {
            reason = Wire.ascii(reason, 128);
            if (reason.isEmpty()) {
                reason = "the serving side refused the connection";
            }
            refuse(502, reason);
        }
    }
}
