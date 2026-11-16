package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * The forwarders' copy loop: one connection through the tunnel and one
 * local TCP connection, both ways, with half-closes passed on and a reason
 * that names the hop that broke.
 *
 * <pre>
 * application -- connect side == hub == serve side -- target
 * </pre>
 */
final class Bridge {
    /** The ends of the chain as one side sees them, so that a reason can say which hop broke. */
    static final class Party {
        final String self; // this program
        final String local; // what its TCP connection goes to
        final String far; // what is at the other end of the tunnel

        private Party(String self, String local, String far) {
            this.self = self;
            this.local = local;
            this.far = far;
        }
    }

    static final Party SERVE = new Party("pfrelay-java serve", "the target", "the application");
    static final Party CONNECT = new Party("pfrelay-java connect", "the application", "the target");

    static final int TARGET_DIAL_TIMEOUT_MS = 5000;
    /** After a clean finish, how long the far end's close may run ahead of our own last result. */
    private static final long SETTLE_MS = 200;

    private Bridge() {}

    /** How one direction stopped. Both null: its source finished cleanly. */
    private static final class End {
        final boolean outbound; // local -> tunnel
        final IOException readErr;
        final IOException writeErr;

        End(boolean outbound, IOException readErr, IOException writeErr) {
            this.outbound = outbound;
            this.readErr = readErr;
            this.writeErr = writeErr;
        }

        boolean clean() {
            return readErr == null && writeErr == null;
        }
    }

    /** One direction's end, worded. mine: the cause is on this side, which the far end cannot see. */
    private static final class Verdict {
        final String reason;
        final boolean mine;
        final IOException err;

        Verdict(String reason, boolean mine, IOException err) {
            this.reason = reason;
            this.mine = mine;
            this.err = err;
        }
    }

    static InetSocketAddress parseHostPort(String target) {
        int colon = target == null ? -1 : target.lastIndexOf(':');
        if (colon <= 0) {
            throw new IllegalArgumentException("the target must be host:port, not \"" + target + "\"");
        }
        String host = target.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        int port;
        try {
            port = Integer.parseInt(target.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("the target must be host:port, not \"" + target + "\"");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("the target's port is out of range: " + target);
        }
        return InetSocketAddress.createUnresolved(host, port);
    }

    /** Connects to the target. */
    static Socket dialTarget(String target) throws IOException {
        InetSocketAddress a = parseHostPort(target);
        Socket s = new Socket();
        try {
            s.setTcpNoDelay(true);
            s.connect(new InetSocketAddress(a.getHostString(), a.getPort()), TARGET_DIAL_TIMEOUT_MS);
            return s;
        } catch (IOException e) {
            closeQuietly(s);
            throw e;
        }
    }

    static void closeQuietly(java.io.Closeable c) {
        try {
            c.close();
        } catch (IOException ignored) {
            // done with it
        }
    }

    private static End copy(boolean outbound, InputStream in, OutputStream out) {
        byte[] buf = new byte[Conn.CHUNK];
        while (true) {
            int n;
            try {
                n = in.read(buf);
            } catch (IOException e) {
                return new End(outbound, e, null);
            }
            if (n < 0) {
                return new End(outbound, null, null);
            }
            try {
                out.write(buf, 0, n);
            } catch (IOException e) {
                return new End(outbound, null, e);
            }
        }
    }

    private static String linkReason(Party p, IOException e) {
        if (e instanceof RemoteException) {
            return ((RemoteException) e).reason();
        }
        if (e instanceof SocketTimeoutException) {
            return "the link between " + p.self + " and the server was silent";
        }
        return "the link between " + p.self + " and the server was lost (" + e.getMessage() + ")";
    }

    private static String localReason(Party p, IOException e) {
        String m = String.valueOf(e.getMessage()).toLowerCase(java.util.Locale.ROOT);
        if (m.contains("reset") || m.contains("broken pipe")) {
            return p.local + " reset its connection to " + p.self;
        }
        return "the connection between " + p.self + " and " + p.local + " failed (" + e.getMessage() + ")";
    }

    private static Verdict describe(Party p, End r) {
        if (r.clean()) {
            return r.outbound ? new Verdict(p.local + " closed the connection", true, null)
                    : new Verdict(p.far + " closed the connection", false, null);
        }
        if (r.outbound && r.readErr != null) {
            return new Verdict(localReason(p, r.readErr), true, r.readErr);
        }
        if (r.outbound) {
            return new Verdict(linkReason(p, r.writeErr), false, r.writeErr);
        }
        if (r.readErr != null) {
            // a silent link may still carry what this end sends, so say so
            return new Verdict(linkReason(p, r.readErr), r.readErr instanceof SocketTimeoutException, r.readErr);
        }
        return new Verdict(localReason(p, r.writeErr), true, r.writeErr);
    }

    /**
     * Copies both ways until both directions finish cleanly or either
     * fails, then closes both ends. When this end saw the break, it tells
     * the far end why, so that both sides name the same cause.
     */
    static void run(Client client, Conn conn, Socket local, Party p, Forwarder f) {
        BlockingQueue<End> results = new ArrayBlockingQueue<>(2);
        Sched.go(() -> {
            End e;
            try {
                e = copy(true, local.getInputStream(), conn.getOutputStream());
                if (e.clean()) {
                    try {
                        conn.shutdownOutput();
                    } catch (IOException x) {
                        e = new End(true, null, x);
                    }
                }
            } catch (IOException x) {
                e = new End(true, x, null);
            }
            results.add(e);
        });
        Sched.go(() -> {
            End e;
            try {
                e = copy(false, conn.getInputStream(), local.getOutputStream());
                if (e.clean()) {
                    try {
                        local.shutdownOutput();
                    } catch (IOException ignored) {
                        // the local side is gone; the other direction will say so
                    }
                }
            } catch (IOException x) {
                e = new End(false, null, x);
            }
            results.add(e);
        });

        Verdict v;
        try {
            v = describe(p, results.take());
            if (v.err != null && !v.mine && !(v.err instanceof RemoteException)
                    && conn.error() instanceof RemoteException) {
                // The far end's reason over what it caused here: a write
                // that failed because the far end had gone (§13.5).
                RemoteException r = (RemoteException) conn.error();
                v = new Verdict(r.reason(), false, r);
            }
            if (v.err == null) {
                // One direction finished cleanly. If that was the far end's
                // half-close, nothing reads the stream any more, so watch for
                // the far end going away while this end still has the floor.
                End second = null;
                while (second == null && !conn.isGone()) {
                    second = results.poll(50, TimeUnit.MILLISECONDS);
                }
                if (second == null) {
                    second = results.poll(SETTLE_MS, TimeUnit.MILLISECONDS);
                }
                if (second != null) {
                    Verdict v2 = describe(p, second);
                    if (v2.err != null) {
                        v = v2;
                    }
                } else {
                    String why = conn.goneReason();
                    IOException broken = conn.error(); // such as a framed stream broken after the far end's eof
                    IOException err = why != null ? new RemoteException(why)
                            : broken != null ? broken : new IOException("the server closed the connection");
                    String reason = why != null ? why
                            : broken != null ? linkReason(p, broken) : "the server closed the connection";
                    v = new Verdict(reason, false, err);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            v = new Verdict(p.self + " is stopping", true, new java.io.InterruptedIOException("interrupted"));
        }
        if (f != null && f.isClosed()) {
            v = new Verdict(p.self + " is stopping", true, new IOException(p.self + " is stopping"));
        }
        if (v.err == null) {
            conn.close();
        } else if (v.mine) {
            conn.failWith(v.reason, v.err);
        } else {
            conn.abortWith(v.err);
        }
        closeQuietly(local);
        ConnInfo info = conn.info();
        client.log("connection " + conn.id().shortForm() + " closed: sent " + info.sent() + " B, received "
                + info.received() + " B; " + v.reason);
    }
}
