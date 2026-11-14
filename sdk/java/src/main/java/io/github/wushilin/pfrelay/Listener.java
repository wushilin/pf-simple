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
            try {
                ws = client.openWs(Endpoint.SERVE, new java.util.LinkedHashMap<>(h));
            } catch (IOException e) {
                err = e;
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
                IOException lost = control(ws, timing);
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

    private void giveUp(IOException e) {
        finalError = e;
        registered.countDown();
    }

    /** Runs one control channel until it fails (docs/PROTOCOL.md §7). */
    private IOException control(WebSocket ws, Timing timing) {
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
                            Sched.go(() -> open(id));
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

    /** Answers the hub's request for connection id. */
    private void open(String id) {
        if (target != null) {
            forward(id);
            return;
        }
        if (!slots.tryAcquire()) {
            client.log("connection " + Client.shortId(id) + " refused: " + BACKLOG
                    + " connections are waiting to be accepted");
            client.refuse(id, REASON_BACKLOG);
            return;
        }
        Conn c;
        try {
            WebSocket ws = client.openWs(Endpoint.ACCEPT, client.header(id));
            c = new Conn(ws, client, new ConnId(id), Side.SERVE);
        } catch (IOException e) {
            slots.release();
            client.log("connection " + Client.shortId(id) + " failed: cannot bring it to the server: "
                    + e.getMessage());
            return;
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

    /**
     * Carries connection id to the target. The target is reached first, so
     * that one that cannot be reached is refused with a reason the
     * connecting side hears at once (docs/PROTOCOL.md §9).
     */
    private void forward(String id) {
        String shortId = Client.shortId(id);
        java.net.Socket local;
        try {
            local = Bridge.dialTarget(target);
        } catch (IOException | IllegalArgumentException e) {
            client.log("connection " + shortId + " failed: cannot reach the target " + target + ": "
                    + e.getMessage());
            client.refuse(id, REASON_UNREACHABLE);
            return;
        }
        Conn c;
        try {
            c = new Conn(client.openWs(Endpoint.ACCEPT, client.header(id)), client, new ConnId(id), Side.SERVE);
        } catch (IOException e) {
            client.log("connection " + shortId + " failed: cannot bring it to the server: " + e.getMessage());
            Bridge.closeQuietly(local);
            return;
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
