package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.net.Socket;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cuts the HTTP requests in flight on behalf of a watcher or a listener
 * when it closes, so that closing does not leave a thread and a socket
 * waiting for a hub that is slow to answer. A thread works for a canceller
 * between {@link #enter()} and closing what it returns; {@link Http#request}
 * registers its socket with that canceller for as long as it runs.
 */
final class Canceller {
    private static final ThreadLocal<Canceller> CURRENT = new ThreadLocal<>();

    private final Set<Socket> inflight = ConcurrentHashMap.newKeySet();
    private final Set<Runnable> hooks = ConcurrentHashMap.newKeySet(); // requests of another transport (Transport)
    private volatile boolean cancelled;

    /** Makes this the current thread's canceller until the returned scope is closed. */
    Scope enter() {
        Canceller before = CURRENT.get();
        CURRENT.set(this);
        return () -> CURRENT.set(before);
    }

    /** A thread's time working for a canceller. */
    interface Scope extends AutoCloseable {
        @Override
        void close();
    }

    static Canceller current() {
        return CURRENT.get();
    }

    /** Registers a request's socket; false, and the socket closed, if this was cancelled already. */
    boolean add(Socket s) {
        inflight.add(s);
        if (cancelled) {
            inflight.remove(s);
            close(s);
            return false;
        }
        return true;
    }

    /** Runs cancel when this is cancelled, at once if it was; closing the result forgets it. */
    AutoCloseable hook(Runnable cancel) {
        hooks.add(cancel);
        if (cancelled && hooks.remove(cancel)) {
            cancel.run();
        }
        return () -> hooks.remove(cancel);
    }

    void remove(Socket s) {
        inflight.remove(s);
    }

    /** Cuts every request in flight, and every one started from now on. */
    void cancel() {
        cancelled = true;
        for (Socket s : inflight) {
            close(s);
        }
        inflight.clear();
        for (Runnable r : hooks) {
            if (hooks.remove(r)) {
                try {
                    r.run();
                } catch (RuntimeException ignored) {
                    // cut anyway
                }
            }
        }
    }

    boolean isCancelled() {
        return cancelled;
    }

    private static void close(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // cut
        }
    }
}
