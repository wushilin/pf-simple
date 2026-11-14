package io.github.wushilin.pfrelay;

import java.io.Closeable;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

/**
 * A running forwarder: {@link Client#serve(String)}, which carries the
 * tunnel's connections to a TCP target, or {@link Client#connect}, which
 * carries local TCP connections through the tunnel. It runs on its own
 * threads until {@link #close()}.
 */
public final class Forwarder implements Closeable {
    private final Closeable stop;
    private final BooleanSupplier up;
    private final String stopping;
    private final Set<Conn> active = ConcurrentHashMap.newKeySet();
    private volatile boolean closed;

    Forwarder(Closeable stop, BooleanSupplier up, String stopping) {
        this.stop = stop;
        this.up = up;
        this.stopping = stopping;
    }

    /**
     * For serving: whether the tunnel is registered with the hub right now.
     * For connecting: whether the forwarder is still running.
     */
    public boolean isUp() {
        return !closed && up.getAsBoolean();
    }

    /** Whether {@link #close()} was called. */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Stops: no new connections are taken, and the connections it carries
     * are dropped, telling their far ends that this side is stopping.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            stop.close();
        } catch (java.io.IOException ignored) {
            // stopping anyway
        }
        for (Conn c : active) {
            c.fail(stopping);
        }
    }

    /** Tracks a carried connection; false if the forwarder is closed already. */
    boolean track(Conn c) {
        active.add(c);
        if (closed) {
            active.remove(c);
            return false;
        }
        return true;
    }

    void untrack(Conn c) {
        active.remove(c);
    }
}
