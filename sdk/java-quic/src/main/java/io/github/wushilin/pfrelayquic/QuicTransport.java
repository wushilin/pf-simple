package io.github.wushilin.pfrelayquic;

import io.github.wushilin.pfrelay.AccessDeniedException;
import io.github.wushilin.pfrelay.StatusException;
import io.github.wushilin.pfrelay.Transport;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
    static final String PATH = "/pf/api/tunnel/quic";
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

    private QConn conn; // guarded by this

    @Override
    public String name() {
        return "QUIC";
    }

    @Override
    public void close() {
        QConn qc;
        synchronized (this) {
            qc = conn;
            conn = null;
        }
        if (qc != null) {
            qc.close(Wire.CODE_NONE, "done");
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
        HttpAnswer a = p.get(PATH, h);
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
    synchronized QConn get(Params p, String op) throws IOException {
        if (conn != null && conn.alive()) {
            return conn;
        }
        conn = null;
        for (int attempt = 0;; attempt++) {
            Discovery d = discover(p, op);
            Pin pin = new Pin(d.fingerprints());
            try {
                conn = dial(d, pin);
                return conn;
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
        if (lower.contains("version negotiation") || lower.contains("doesn't support")) {
            return new IOException("the hub's QUIC listener does not speak QUIC version 1");
        }
        if (lower.contains("connection_refused") || lower.contains("connection refused")) {
            return new StatusException(429, "the hub refused the QUIC connection; trying again later");
        }
        return new IOException("cannot reach the hub over QUIC (UDP may be blocked on the way; pf-client over "
                + "WebSocket works where QUIC does not): " + m, e);
    }

    /** Forgets qc as the connection to use, if it still is. */
    private synchronized void drop(QConn qc) {
        if (conn == qc) {
            conn = null;
        }
    }

    // ---------- requests ----------

    /** A request's stream and the hub's answer to it. */
    private record Answered(QConn qc, QuicStream s, Map<String, Object> answer) {}

    /**
     * Opens a stream, sends the request, and reads the hub's answer. A
     * refusal is thrown, after the stream is ended (§13.5).
     */
    private Answered request(Params p, String discoveryOp, Wire.Obj req) throws IOException {
        QConn qc = get(p, discoveryOp);
        req.put("proto", Integer.toString(Wire.PROTO)).put("version", p.agent()).put("word", p.word());
        byte[] msg = Wire.encode(req.toString());
        QuicStream s;
        try {
            s = qc.c.createStream(true);
        } catch (IOException | RuntimeException e) {
            drop(qc);
            throw new IOException("the QUIC connection to the hub was lost: " + e.getMessage(), e);
        }
        AtomicBoolean cancelled = new AtomicBoolean();
        AtomicBoolean timedOut = new AtomicBoolean();
        Map<String, Object> a;
        AutoCloseable hook = p.whenCancelled(() -> {
            cancelled.set(true);
            QStream.reset(s, Wire.CODE_CANCELLED);
        });
        try {
            ScheduledFuture<?> deadline = Bg.after(ANSWER_WAIT_MS, () -> {
                timedOut.set(true);
                QStream.reset(s, Wire.CODE_REQUEST_TIMEOUT);
            });
            try {
                s.getOutputStream().write(msg);
                s.getOutputStream().flush();
                a = Wire.read(s.getInputStream());
                if (a == null) {
                    throw new Wire.MessageException("the stream ended before the answer");
                }
            } catch (IOException e) {
                QStream.reset(s, timedOut.get() ? Wire.CODE_REQUEST_TIMEOUT : Wire.CODE_PROTOCOL);
                if (cancelled.get()) {
                    throw new InterruptedIOException("cancelled");
                }
                if (!qc.alive()) {
                    throw new IOException("the QUIC connection to the hub was lost (" + qc.why() + ")");
                }
                if (timedOut.get()) {
                    throw new IOException("the hub did not answer within " + ANSWER_WAIT_MS / 1000 + "s");
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
        int proto = Wire.num(a, "proto");
        if (proto != 0 && proto != Wire.PROTO) {
            QStream.reset(s, Wire.CODE_PROTOCOL);
            throw new IOException("the hub answered in QUIC protocol " + proto + "; this client speaks " + Wire.PROTO);
        }
        int status = Wire.num(a, "status");
        if (status != 200 && status != 204) {
            // The hub sends FIN and STOP_SENDING: end this direction too (§13.5).
            try {
                s.resetStream(Wire.CODE_REFUSED);
            } catch (RuntimeException ignored) {
                // ended already
            }
            QStream.drain(s);
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
        return new Answered(qc, s, a);
    }

    @Override
    public void check(Params p) throws IOException {
        Wire.Obj req = new Wire.Obj().put("op", "check").put("clientToken", p.clientToken());
        Answered r = request(p, "connect", req);
        QStream.finishAndDrain(r.s);
    }

    @Override
    public Dialed connect(Params p) throws IOException {
        Wire.Obj req = new Wire.Obj().put("op", "connect").put("clientToken", p.clientToken());
        Answered r = request(p, "connect", req);
        return new Dialed(new QStream(r.s), Wire.str(r.answer, "conn"));
    }

    @Override
    public Registration register(Params p, String target) throws IOException {
        Wire.Obj req = new Wire.Obj().put("op", "serve").put("serveToken", p.serveToken()).put("name", p.name())
                .put("target", target).put("clientTokenSHA256", p.clientTokenSha256());
        QConn qc = get(p, "serve");
        qc.serving(1); // an open may arrive before the answer (§13.4)
        Answered r;
        try {
            r = request(p, "serve", req);
        } finally {
            qc.serving(-1);
        }
        Reg reg = new Reg(r.qc, r.s, Wire.str(r.answer, "reg"));
        r.qc.add(reg);
        Bg.go(reg::watch);
        return reg;
    }

    // ---------- one QUIC connection ----------

    /** One QUIC connection to the hub, and its registrations. */
    static final class QConn {
        final QuicClientConnection c;
        private final Map<String, Reg> regs = new HashMap<>(); // guarded by this
        private int serves; // serve requests not yet answered; guarded by this
        private volatile boolean dead;
        private volatile String why = "";
        private ScheduledFuture<?> pinger;

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
            pinger = Bg.every(PING_EVERY_MS, () -> {
                if (dead) {
                    return;
                }
                try {
                    ((QuicConnectionImpl) c).send(new PingFrame(), f -> {}, true);
                } catch (LinkageError e) {
                    // kwik on the module path hides its implementation: fall
                    // back to its own keepalive, which pings less often
                    pinger.cancel(false);
                    c.keepAlive(Integer.MAX_VALUE / 2);
                } catch (RuntimeException ignored) {
                    // the connection is going
                }
            });
            if (dead) {
                pinger.cancel(false);
            }
        }

        void close(long code, String reason) {
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
            if (pinger != null) {
                pinger.cancel(false);
            }
            for (Reg r : all) {
                r.end(new IOException("the link to the server was lost (" + reason + ")"));
            }
        }

        synchronized void serving(int d) {
            serves += d;
            notifyAll();
        }

        synchronized void add(Reg r) {
            regs.put(r.id, r);
            notifyAll();
            if (dead) {
                Bg.go(() -> r.end(new IOException("the link to the server was lost (" + why + ")")));
            }
        }

        synchronized void remove(Reg r) {
            regs.remove(r.id, r);
            notifyAll();
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
            ScheduledFuture<?> deadline = Bg.after(REQUEST_WAIT_MS, () -> QStream.reset(s, Wire.CODE_REQUEST_TIMEOUT));
            Map<String, Object> m;
            try {
                m = Wire.read(s.getInputStream());
            } catch (IOException e) {
                deadline.cancel(false);
                QStream.reset(s, Wire.CODE_PROTOCOL);
                return;
            }
            if (!deadline.cancel(false)) {
                return; // timed out, and reset
            }
            String id = m == null ? "" : Wire.str(m, "open");
            if (id.isEmpty()) {
                QStream.reset(s, Wire.CODE_PROTOCOL);
                return;
            }
            Reg r;
            try {
                r = find(Wire.str(m, "reg"));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                QStream.reset(s, Wire.CODE_CANCELLED);
                return;
            }
            OpenImpl o = new OpenImpl(s, id);
            if (r == null || !r.deliver(o)) {
                o.answerAndFinish(new Wire.Obj().put("status", 410).put("error", "no such registration"));
            }
        }
    }

    // ---------- a registration ----------

    /** One registration over QUIC, until its serve stream ends. */
    static final class Reg implements Registration {
        private static final Object END = new Object();

        private final QConn qc;
        private final QuicStream s;
        final String id;
        private final ArrayBlockingQueue<Object> opens = new ArrayBlockingQueue<>(BACKLOG + 1);
        private volatile IOException why;
        private final AtomicBoolean ended = new AtomicBoolean();

        Reg(QConn qc, QuicStream s, String id) {
            this.qc = qc;
            this.s = s;
            this.id = id;
        }

        boolean deliver(OpenImpl o) {
            if (ended.get()) {
                return false;
            }
            return opens.offer(o);
        }

        /** Reads the serve stream until it ends: the hub's end message, its FIN, or a lost connection. */
        void watch() {
            IOException e;
            while (true) {
                Map<String, Object> m;
                try {
                    m = Wire.read(s.getInputStream());
                } catch (IOException x) {
                    e = ended.get() ? new IOException("unregistered")
                            : new IOException("the link to the server was lost (" + (qc.alive() ? x.getMessage() : qc.why()) + ")");
                    break;
                }
                if (m == null) { // the hub's FIN: answer with ours
                    e = new IOException("the server ended the registration");
                    QStream.finishAndDrain(s);
                    break;
                }
                String end = Wire.str(m, "end");
                if (end.isEmpty()) {
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
                QStream.finishAndDrain(s); // the hub's FIN follows; answer with ours
                break;
            }
            end(e);
        }

        void end(IOException e) {
            if (ended.compareAndSet(false, true)) {
                why = e;
                opens.offer(END);
                qc.remove(this);
                // opens that were not taken: nobody will
                Object o;
                while ((o = opens.poll()) != null) {
                    if (o instanceof OpenImpl) {
                        ((OpenImpl) o).answerAndFinish(new Wire.Obj().put("status", 410).put("error", "no such registration"));
                    }
                }
                opens.offer(END);
            }
        }

        @Override
        public Open next() throws IOException {
            while (true) {
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
        }

        /** Unregisters: FIN on the serve stream (§13.4). */
        @Override
        public void close() {
            boolean first = !ended.get();
            end(new IOException("unregistered"));
            if (first) {
                QStream.finishAndDrain(s);
            }
        }
    }

    // ---------- an open ----------

    /** The hub asking for one connection, on a stream it opened. */
    static final class OpenImpl implements Open {
        private final QuicStream s;
        private final String id;
        private final AtomicBoolean answered = new AtomicBoolean();

        OpenImpl(QuicStream s, String id) {
            this.s = s;
            this.id = id;
        }

        @Override
        public String id() {
            return id;
        }

        private void write(Wire.Obj a) throws IOException {
            ScheduledFuture<?> watchdog = Bg.after(WRITE_TIMEOUT_MS, () -> QStream.reset(s, Wire.CODE_BROKEN));
            try {
                Wire.write(s.getOutputStream(), a.toString());
            } finally {
                watchdog.cancel(false);
            }
        }

        /** A refusal: the answer, then FIN (§13.5). */
        void answerAndFinish(Wire.Obj a) {
            if (!answered.compareAndSet(false, true)) {
                return;
            }
            try {
                write(a);
            } catch (IOException ignored) {
                // the stream is gone
            }
            QStream.finishAndDrain(s);
        }

        @Override
        public Stream accept() throws IOException {
            if (!answered.compareAndSet(false, true)) {
                throw new IOException("this connection was answered already");
            }
            try {
                write(new Wire.Obj().put("status", 200));
            } catch (IOException e) {
                QStream.reset(s, Wire.CODE_BROKEN);
                throw e;
            }
            return new QStream(s);
        }

        @Override
        public void refuse(String reason) {
            reason = Wire.ascii(reason, 128);
            if (reason.isEmpty()) {
                reason = "the serving side refused the connection";
            }
            answerAndFinish(new Wire.Obj().put("status", 502).put("error", reason));
        }
    }
}
