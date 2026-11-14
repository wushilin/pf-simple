package io.github.wushilin.pfrelay;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The SDK's threads: a timer that only triggers, and a pool for whatever
 * blocks. All of them are daemons, so they never keep a program alive.
 */
final class Sched {
    private static final AtomicInteger SEQ = new AtomicInteger();

    private static ThreadFactory daemons(String prefix) {
        return r -> {
            Thread t = new Thread(r, prefix + "-" + SEQ.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    private static final ScheduledThreadPoolExecutor TIMER;
    private static final ExecutorService POOL = Executors.newCachedThreadPool(daemons("pfrelay"));

    static {
        TIMER = new ScheduledThreadPoolExecutor(2, daemons("pfrelay-timer"));
        TIMER.setRemoveOnCancelPolicy(true);
    }

    private Sched() {}

    /** Runs r on the pool once ms have passed. r should not block for long. */
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
