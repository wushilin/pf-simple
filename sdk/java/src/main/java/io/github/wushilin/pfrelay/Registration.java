package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

/**
 * One control channel's life (tunnel protocol 2, docs/PROTOCOL.md §12): its
 * session secret, and the idle legs that belong to it.
 *
 * <p>A registration with a protocol 2 hub brings a session secret. Each
 * accept sends it back, and the hub may offer reuse. When a connection on
 * an offered leg finishes cleanly, the hub says "idle"; this side answers
 * "idle" to keep the leg, which then waits for the hub's "bind &lt;id&gt;":
 * the next connection, answered at once with "bound &lt;id&gt;".
 */
final class Registration {
    static final String IDLE = "idle";
    static final byte[] IDLE_TEXT = IDLE.getBytes(StandardCharsets.US_ASCII);
    static final String BIND = "bind";
    static final String BOUND = "bound";
    static final String H_SESSION = "X-PF-Tunnel-Session";
    static final String H_KEEP_ALIVE = "X-PF-Tunnel-Keep-Alive";
    /** How an attempt ends whose leg died before the hub heard "bound": the hub asks again (§12.7). */
    static final String REASON_LEG_LOST = "the leg was lost before the server took the connection";

    /** Carries a connection the hub asked for: with an open message (leg null), or bound on an idle leg. */
    interface Opener {
        void open(Registration reg, String id, WebSocket leg);
    }

    private final Client client;
    /** The session secret; null when the hub does not reuse legs here. Never logged. */
    final String session;
    private final Opener opener;
    private final int maxIdle;
    private final Set<WebSocket> legs = ConcurrentHashMap.newKeySet(); // idle, or binding
    private int idle;
    private boolean ended;
    // The ids this registration answered "bound" to, and the ids that came
    // with an open message, remembered for RECALL_MS: an id that came both
    // ways is the case of §12.7, a bound lost with its leg and asked for again.
    private final Map<String, Attempt> bound = new java.util.HashMap<>();
    private final Map<String, Long> opened = new java.util.HashMap<>();

    /** How long ids are remembered: well past the hub's 10 seconds to answer a connection. */
    static final long RECALL_MS = 30_000;

    /** A connection taken on a reused leg; abandoned when the hub asks for it again. */
    private static final class Attempt {
        final long at = System.nanoTime();
        volatile boolean abandoned;
    }

    Registration(Client client, Map<String, String> serveAnswer, Opener opener) {
        this.client = client;
        this.opener = opener;
        this.maxIdle = client.maxIdleLegs();
        String s = null;
        if (client.reuseWanted() && Proto.serverProto(serveAnswer) >= 2) {
            String v = serveAnswer.get(H_SESSION);
            if (v != null && v.length() == 32 && v.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
                s = v;
            }
        }
        this.session = s;
    }

    /** Whether the hub's answer to an accept offered reuse: protocol 2, and a keep-alive of 1 to 3600 (§12.3). */
    static boolean offered(Map<String, String> acceptAnswer) {
        if (Proto.serverProto(acceptAnswer) < 2) {
            return false;
        }
        String v = acceptAnswer.get(H_KEEP_ALIVE);
        if (v == null || v.isEmpty() || v.length() > 4 || !v.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return false;
        }
        int n = Integer.parseInt(v);
        return n >= 1 && n <= 3600;
    }

    private void prune() {
        long now = System.nanoTime();
        bound.values().removeIf(a -> (now - a.at) / 1_000_000 > RECALL_MS);
        opened.values().removeIf(at -> (now - at) / 1_000_000 > RECALL_MS);
    }

    /**
     * Records a bind of id. Refuses one for an id that already came with an
     * open message: a bind that arrives after the hub fell back.
     */
    synchronized boolean takeBind(String id) {
        prune();
        if (opened.containsKey(id)) {
            return false;
        }
        bound.put(id, new Attempt());
        return true;
    }

    /**
     * Records an open message for id, and reports whether it is for an id
     * bound here: a new attempt, the old one being abandoned (§12.7).
     */
    synchronized boolean tookOpen(String id) {
        prune();
        opened.put(id, System.nanoTime());
        Attempt a = bound.get(id);
        if (a != null) {
            a.abandoned = true;
            return true;
        }
        return false;
    }

    /** Whether the attempt at id on a reused leg was given up, because the hub asked for it again. */
    synchronized boolean abandoned(String id) {
        Attempt a = bound.get(id);
        return a != null && a.abandoned;
    }

    /** Reserves room for one more idle leg. */
    synchronized boolean keep() {
        if (ended || idle >= maxIdle) {
            return false;
        }
        idle++;
        return true;
    }

    synchronized void release() {
        idle--;
    }

    synchronized int idleCount() {
        return idle;
    }

    /** The control channel ended: every idle or binding leg goes with it (§12.9). */
    void end() {
        synchronized (this) {
            ended = true;
        }
        for (WebSocket ws : legs) {
            ws.abort();
        }
        legs.clear();
    }

    synchronized boolean isEnded() {
        return ended;
    }

    /**
     * Takes over an idle leg, kept with keep(): it waits on a thread of its
     * own for the hub's "bind", keeping the leg alive, until the leg or the
     * registration ends.
     */
    void idleLeg(WebSocket ws) {
        legs.add(ws);
        if (isEnded()) {
            legs.remove(ws);
            ws.abort();
            release();
            return;
        }
        Sched.go(() -> waitForBind(ws));
    }

    private void waitForBind(WebSocket ws) {
        Timing timing = client.timing();
        boolean bound = false;
        ScheduledFuture<?> pinger = null;
        try {
            ws.setReadTimeout(timing.linkSilenceMs());
            ws.setWriteTimeout(Client.CONTROL_WRITE_TIMEOUT_MS);
            pinger = Sched.every(timing.pingEveryMs(), () -> {
                try {
                    ws.tryWriteFrame(WebSocket.OP_PING, new byte[0]);
                } catch (IOException e) {
                    ws.abort();
                }
            });
            while (true) {
                WebSocket.Frame f = ws.readHeader();
                if (f.op == WebSocket.OP_PING || f.op == WebSocket.OP_PONG) {
                    ws.readPayload(f, 125);
                    continue;
                }
                if (f.op != WebSocket.OP_TEXT) {
                    return; // a close, or a violation (§12.4)
                }
                String msg = new String(ws.readPayload(f, Conn.MAX_TEXT_FRAME), StandardCharsets.UTF_8);
                String prefix = BIND + " ";
                if (!msg.startsWith(prefix) || msg.length() == prefix.length()) {
                    if (knownLegFrame(msg)) {
                        return; // a known frame in the wrong state: a violation (§12.4)
                    }
                    continue; // unknown text is ignored, as on any stream (§8.1)
                }
                String id = msg.substring(prefix.length());
                pinger.cancel(false);
                pinger = null;
                if (!legs.remove(ws) || isEnded()) {
                    return;
                }
                if (!takeBind(id)) {
                    return; // already asked for with an open message: the hub gave this leg up
                }
                // answered at once, before anything else (§12.7)
                ws.writeFrame(WebSocket.OP_TEXT, (BOUND + " " + id).getBytes(StandardCharsets.UTF_8));
                bound = true;
                release();
                ws.setWriteTimeout(0);
                client.log("connection " + Client.shortId(id) + " arrived on a reused leg");
                opener.open(this, id, ws);
                return;
            }
        } catch (IOException e) {
            // closed, dead or silent
        } finally {
            if (pinger != null) {
                pinger.cancel(false);
            }
            if (!bound) {
                // every other way out gives the leg's place back: the hub
                // closed it, a dead or silent link, a violation, or the
                // registration ending
                legs.remove(ws);
                release();
                ws.abort();
            }
        }
    }

    /**
     * Whether msg is one of the text frames of streams and reused legs
     * (§8.1, §12): such a frame where it does not belong is a violation,
     * while any other text is ignored.
     */
    static boolean knownLegFrame(String msg) {
        return msg.equals("eof") || msg.equals(IDLE) || msg.equals(BIND) || msg.equals(BOUND)
                || msg.startsWith("err:") || msg.startsWith(BIND + " ") || msg.startsWith(BOUND + " ");
    }

    /** Refuses a connection that arrived on a reused leg: after "bound", that is err: and a close (§12.7). */
    static void failLeg(WebSocket ws, String reason) {
        ws.beginClose();
        try {
            ws.writeFrame(WebSocket.OP_TEXT, ("err:" + Conn.cleanReason(reason, 128)).getBytes(StandardCharsets.UTF_8));
            ws.writeFrame(WebSocket.OP_CLOSE, new byte[0]);
        } catch (IOException ignored) {
            // the leg is gone already
        }
        ws.abort();
    }
}
