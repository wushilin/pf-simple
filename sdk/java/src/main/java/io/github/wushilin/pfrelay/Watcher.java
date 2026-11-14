package io.github.wushilin.pfrelay;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Checks, until closed, whether the tunnel can be reached
 * ({@link Client#watch()}). {@link ClientEvents#onTunnel} hears the first
 * result and then every change. A tunnel that is up is checked every 30
 * seconds; one that is down sooner, from 1 second doubling to 30.
 */
public final class Watcher implements Closeable {
    private final Client client;
    private final CountDownLatch stopped = new CountDownLatch(1);
    private volatile Boolean up; // null until the first result
    private volatile IOException lastError;

    Watcher(Client client) {
        this.client = client;
    }

    void start() {
        Thread t = new Thread(this::run, "pfrelay-watch-" + client.wordLabel());
        t.setDaemon(true);
        t.start();
    }

    /** Whether the last check found the tunnel up; false before the first result. */
    public boolean isUp() {
        return Boolean.TRUE.equals(up);
    }

    /** Why the last check found the tunnel down; null while it is up. */
    public IOException lastError() {
        return lastError;
    }

    @Override
    public void close() {
        stopped.countDown();
    }

    private void run() {
        Timing timing = client.timing();
        long backoff = timing.retryMinMs();
        while (stopped.getCount() > 0) {
            IOException err = null;
            try {
                client.check();
            } catch (IOException e) {
                err = e;
            } catch (RuntimeException e) {
                err = new IOException(e.getMessage(), e);
            }
            if (stopped.getCount() == 0) {
                return;
            }
            boolean now = err == null;
            Boolean before = up;
            up = now;
            lastError = err;
            if (before == null || before != now) {
                client.log(now ? "the tunnel is up" : "the tunnel is not available (" + err.getMessage() + ")");
                client.tunnel(now, err);
            }
            long wait;
            if (now) {
                wait = timing.recheckMs();
                backoff = timing.retryMinMs();
            } else {
                wait = backoff;
                backoff = timing.next(backoff);
            }
            try {
                if (stopped.await(wait, TimeUnit.MILLISECONDS)) {
                    return;
                }
            } catch (InterruptedException e) {
                return;
            }
        }
    }
}
