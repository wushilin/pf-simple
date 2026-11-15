package io.github.wushilin.pfrelayquic;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** The SDK's threads: a timer that only triggers, and a pool for what blocks. All daemons. */
final class Bg {
    private static final AtomicInteger SEQ = new AtomicInteger();

    private static ThreadFactory daemons(String prefix) {
        return r -> {
            Thread t = new Thread(r, prefix + "-" + SEQ.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    private static final ScheduledThreadPoolExecutor TIMER;
    private static final ExecutorService POOL = Executors.newCachedThreadPool(daemons("pfrelay-quic"));

    static {
        TIMER = new ScheduledThreadPoolExecutor(1, daemons("pfrelay-quic-timer"));
        TIMER.setRemoveOnCancelPolicy(true);
    }

    private Bg() {}

    /** Runs r on the pool once ms have passed. */
    static ScheduledFuture<?> after(long ms, Runnable r) {
        return TIMER.schedule(() -> POOL.execute(r), ms, TimeUnit.MILLISECONDS);
    }

    /** Runs r on the pool every ms, starting ms from now. */
    static ScheduledFuture<?> every(long ms, Runnable r) {
        return TIMER.scheduleAtFixedRate(() -> POOL.execute(r), ms, ms, TimeUnit.MILLISECONDS);
    }

    /** Runs r on a pool thread now. */
    static void go(Runnable r) {
        POOL.execute(r);
    }
}
