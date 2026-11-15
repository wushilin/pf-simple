package io.github.wushilin.pfrelay;

import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Serves the tunnel and hands each connection to {@link #accept()}. It
 * keeps itself registered with the hub: a lost hub is registered with
 * again, with a growing pause, until {@link #close()}. Connections that
 * were open end when the hub is lost; the connecting side opens new ones.
 */
public final class Listener implements Closeable {
    /** How many connections may wait for accept; more are refused, and their connecting side is told why. */
    static final int BACKLOG = 128;

    private final Client client;
    private final Semaphore slots = new Semaphore(BACKLOG);
    private final ArrayDeque<Conn> queue = new ArrayDeque<>();
    private final CountDownLatch stopped = new CountDownLatch(1);
    private final CountDownLatch registered = new CountDownLatch(1);
    private volatile IOException finalError;
    private volatile boolean up;
    private volatile WebSocket control;
    private volatile boolean closed;
    private final Canceller canceller = new Canceller(); // requests in flight, cut by close()
    /** For a serve forwarder: the target, and the forwarder; null for a listener. */
    private final String target;
    volatile Forwarder forwarder;

    Listener(Client client, String target) {
        this.client = client;
        this.target = target;
    }

    /** Registers, and returns once registered; throws on a final refusal. */
    void register(Duration timeout) throws IOException {
        client.checkServable();
        start();
        awaitRegistered(timeout);
    }

    private void start() {
        Thread t = new Thread(this::serve, "pfrelay-serve-" + client.wordLabel());
        t.setDaemon(true);
        t.start();
    }

    private void awaitRegistered(Duration timeout) throws IOException {
        try {
            boolean done;
            if (timeout == null) {
                registered.await();
                done = true;
            } else {
                done = registered.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
            }
            if (finalError != null) {
                close();
                throw finalError;
            }
            if (!done) {
                close();
                throw new InterruptedIOException("the tunnel was not registered within " + timeout);
            }
        } catch (InterruptedException e) {
            close();
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted while registering");
        }
    }

    /** Whether the tunnel is registered with the hub right now. */
    public boolean isUp() {
        return up;
    }

    /**
     * Waits for the next connection.
     *
     * @throws SocketException once the listener is closed
     */
    public Conn accept() throws IOException {
        synchronized (this) {
            while (true) {
                if (closed) {
                    IOException why = finalError;
                    if (why != null) {
                        throw why; // serving gave up, for a reason waiting cannot cure
                    }
                    throw new SocketException("the listener is closed");
                }
                Conn c = queue.poll();
                if (c != null) {
                    slots.release();
                    return c;
                }
                try {
                    wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted");
                }
            }
        }
    }

    /**
     * Stops serving: the registration ends, and connections not yet
     * accepted are dropped. Accepted connections stay open until the hub
     * link they use ends or they are closed.
     */
    @Override
    public void close() {
        ArrayDeque<Conn> drop;
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            drop = new ArrayDeque<>(queue);
            queue.clear();
            notifyAll();
        }
        stopped.countDown();
        registered.countDown();
        canceller.cancel();
        WebSocket ws = control;
        if (ws != null) {
            Sched.go(() -> {
                ws.beginClose();
                try {
                    ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
                } catch (IOException ignored) {
                    // going anyway
                }
                ws.abort();
            });
        }
        for (Conn c : drop) {
            c.fail(REASON_STOPPED);
        }
    }

    /** Sleeps, unless the listener closes first; returns whether it is still open. */
    private boolean sleep(long ms) {
        try {
            return !stopped.await(ms, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            return false;
        }
    }

    // ---------- the registration loop (docs/PROTOCOL.md §9) ----------

    private void serve() {
        Map<String, String> h = client.serveHeader(target);
        Timing timing = client.timing();
        long backoff = timing.retryMinMs();
        boolean served = false;
        String base = client.server();
        for (int attempt = 1;; attempt++) {
            if (closed) {
                return;
            }
            WebSocket ws = null;
            IOException err = null;
            Canceller.Scope scope = canceller.enter();
            try {
                ws = client.openWs(Endpoint.SERVE, new java.util.LinkedHashMap<>(h));
            } catch (IOException e) {
                err = e;
            } finally {
                scope.close();
            }
            if (closed) {
                if (ws != null) {
                    ws.abort();
                }
                return;
            }
            if (err != null) {
                if (err instanceof ProtoException) { // waiting will not change it
                    giveUp(err);
                    return;
                }
                if (!served && err instanceof StatusException && ((StatusException) err).isFinal()) {
                    giveUp(err);
                    return;
                }
                client.log("cannot register with " + base + " (" + err.getMessage() + "); attempt " + attempt
                        + ", trying again in " + backoff / 1000.0 + "s");
            } else {
                client.log((served ? "registered again with " : "registered with ") + base + ": serving \""
                        + client.name() + "\", tunnel " + client.wordLabel() + " -> " + client.target());
                served = true;
                attempt = 0;
                long started = System.nanoTime();
                control = ws;
                up = true;
                registered.countDown();
                if (closed) { // close() may have missed it
                    ws.abort();
                }
                client.serving(true);
                Registration reg = new Registration(client, ws.header, this::open);
                IOException lost = control(ws, timing, reg);
                reg.end(); // its idle legs go with it
                up = false;
                control = null;
                client.serving(false);
                if (closed) {
                    return;
                }
                long lasted = (System.nanoTime() - started) / 1_000_000L;
                if (lasted >= timing.settledMs()) {
                    backoff = timing.retryMinMs();
                }
                client.log("lost the server after " + lasted / 1000.0 + "s (" + lost.getMessage()
                        + "); its connections are closed; registering again in " + backoff / 1000.0 + "s");
            }
            if (!sleep(backoff)) {
                return;
            }
            backoff = timing.next(backoff);
        }
    }

    /**
     * Serving stopped for a reason waiting cannot cure. The listener closes,
     * so that accept() throws the reason instead of waiting for ever.
     */
    private void giveUp(IOException e) {
        finalError = e;
        client.log("serving stopped: " + e.getMessage());
        close();
    }

    /** Runs one control channel until it fails (docs/PROTOCOL.md §7). */
    private IOException control(WebSocket ws, Timing timing, Registration reg) {
        ScheduledFuture<?> pinger = null;
        try {
            ws.setReadTimeout(timing.controlSilenceMs());
            ws.setWriteTimeout(Client.CONTROL_WRITE_TIMEOUT_MS);
            pinger = Sched.every(timing.controlPingMs(), () -> {
                try {
                    ws.tryWriteFrame(WebSocket.OP_PING, new byte[0]);
                } catch (IOException e) {
                    ws.abort();
                }
            });
            while (true) {
                WebSocket.Frame f = ws.readHeader();
                byte[] p = ws.readPayload(f, Client.MAX_CONTROL_FRAME);
                switch (f.op) {
                    case WebSocket.OP_CLOSE:
                        try {
                            byte[] code = new byte[Math.min(2, p.length)];
                            System.arraycopy(p, 0, code, 0, code.length);
                            ws.writeFrame(WebSocket.OP_CLOSE, code);
                        } catch (IOException ignored) {
                            // closing anyway
                        }
                        return new IOException("the server closed the control channel");
                    case WebSocket.OP_PING:
                        ws.writeFrame(WebSocket.OP_PONG, p);
                        break;
                    case WebSocket.OP_TEXT: {
                        String id = openId(new String(p, StandardCharsets.UTF_8));
                        if (id != null) {
                            Sched.go(() -> {
                                if (reg.tookOpen(id)) {
                                    client.abandon(id); // a bound id asked for again: a new attempt (§12.7)
                                }
                                Canceller.Scope scope = canceller.enter();
                                try {
                                    open(reg, id, null);
                                } finally {
                                    scope.close();
                                }
                            });
                        }
                        break;
                    }
                    default:
                        break; // pongs, and anything else the hub has no business sending
                }
            }
        } catch (java.net.SocketTimeoutException e) {
            return new IOException("the control channel was silent for " + timing.controlSilenceMs() / 1000 + "s");
        } catch (IOException e) {
            return e;
        } finally {
            if (pinger != null) {
                pinger.cancel(false);
            }
            ws.abort();
        }
    }

    /** The id in {"open": id}, or null for a message that is not one. */
    static String openId(String text) {
        try {
            Object v = Json.parseObject(text).get("open");
            if (v instanceof String && !((String) v).isEmpty()) {
                return (String) v;
            }
        } catch (IOException ignored) {
            // not for us
        }
        return null;
    }

    /**
     * Answers the hub's request for connection id. leg is the connection's
     * WebSocket when it arrived on a reused leg (the hub already has
     * "bound"); null when it came with an open message, and this side brings
     * a leg to accept.
     */
    private void open(Registration reg, String id, WebSocket leg) {
        if (target != null) {
            forward(reg, id, leg);
            return;
        }
        if (!slots.tryAcquire()) {
            client.log("connection " + Client.shortId(id) + " refused: " + BACKLOG
                    + " connections are waiting to be accepted");
            refuse(id, leg, REASON_BACKLOG);
            return;
        }
        if (leg != null && reg.abandoned(id)) {
            slots.release();
            Registration.failLeg(leg, Registration.REASON_LEG_LOST); // asked for again: the new attempt carries it
            return;
        }
        Conn c;
        try {
            c = leg != null ? new Conn(leg, client, new ConnId(id), Side.SERVE, reg) : client.accept(reg, id);
        } catch (IOException e) {
            slots.release();
            client.log("connection " + Client.shortId(id) + " failed: cannot bring it to the server: "
                    + e.getMessage());
            return;
        }
        if (leg != null && reg.abandoned(id)) {
            client.abandon(id); // asked for again just as it opened
        }
        synchronized (this) {
            if (!closed) {
                queue.add(c);
                notifyAll();
                return;
            }
        }
        slots.release();
        c.fail(REASON_STOPPED);
    }

    /** Refuses connection id: through accept, or after "bound" on its leg with err: (§12.7). */
    private void refuse(String id, WebSocket leg, String reason) {
        if (leg == null) {
            client.refuse(id, reason);
            return;
        }
        client.refused(new ConnId(id), reason);
        Registration.failLeg(leg, reason);
    }

    /**
     * Carries connection id to the target. The target is reached first, so
     * that one that cannot be reached is refused with a reason the
     * connecting side hears at once (docs/PROTOCOL.md §9). On a reused leg,
     * "bound" has gone out already, and a refusal is err: (§12.7).
     */
    private void forward(Registration reg, String id, WebSocket leg) {
        java.net.Socket[] local = new java.net.Socket[1];
        Conn[] conn = new Conn[1];
        boolean done = false;
        try {
            forward(reg, id, leg, local, conn);
            done = true;
        } finally {
            if (!done) { // a RuntimeException: let go of whatever it held
                if (conn[0] != null) {
                    conn[0].fail(Bridge.SERVE.self + " failed");
                } else if (leg != null) {
                    leg.abort();
                }
                if (local[0] != null) {
                    Bridge.closeQuietly(local[0]);
                }
            }
        }
    }

    private void forward(Registration reg, String id, WebSocket leg, java.net.Socket[] held, Conn[] heldConn) {
        String shortId = Client.shortId(id);
        java.net.Socket local;
        try {
            local = Bridge.dialTarget(target);
            held[0] = local;
        } catch (IOException | IllegalArgumentException e) {
            client.log("connection " + shortId + " failed: cannot reach the target " + target + ": "
                    + e.getMessage());
            refuse(id, leg, REASON_UNREACHABLE);
            return;
        }
        if (leg != null && reg.abandoned(id)) {
            // Asked for again while this side was dialing: the new attempt
            // carries it, and this one never opened.
            Bridge.closeQuietly(local);
            Registration.failLeg(leg, Registration.REASON_LEG_LOST);
            return;
        }
        Conn c;
        try {
            c = leg != null ? new Conn(leg, client, new ConnId(id), Side.SERVE, reg) : client.accept(reg, id);
        } catch (IOException e) {
            client.log("connection " + shortId + " failed: cannot bring it to the server: " + e.getMessage());
            Bridge.closeQuietly(local);
            return;
        }
        heldConn[0] = c;
        if (leg != null && reg.abandoned(id)) {
            client.abandon(id); // asked for again just as it opened
        }
        Forwarder f = forwarder;
        if (closed || !f.track(c)) {
            c.fail(Bridge.SERVE.self + " is stopping");
            Bridge.closeQuietly(local);
            return;
        }
        client.log("connection " + shortId + " open: tunnel -> " + target);
        try {
            Bridge.run(client, c, local, Bridge.SERVE, f);
        } finally {
            f.untrack(c);
        }
    }

    static final String REASON_UNREACHABLE = "the serving side could not reach its target";
    static final String REASON_BACKLOG = "the serving side is not accepting connections fast enough";
    static final String REASON_STOPPED = "the serving side stopped listening";

    @Override
    public String toString() {
        return "Listener[" + client.server() + " " + client.wordLabel() + "]";
    }
}
