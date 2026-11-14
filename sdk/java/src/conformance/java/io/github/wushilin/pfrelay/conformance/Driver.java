package io.github.wushilin.pfrelay.conformance;

import io.github.wushilin.pfrelay.AccessDeniedException;
import io.github.wushilin.pfrelay.Client;
import io.github.wushilin.pfrelay.Conn;
import io.github.wushilin.pfrelay.Listener;
import io.github.wushilin.pfrelay.ProtoException;
import io.github.wushilin.pfrelay.ServerInfo;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * The Java SDK's conformance driver: the small program the conformance
 * suite runs to put the SDK through its cases (conformance/README.md). It
 * uses only the SDK's public API, as an application would.
 */
public final class Driver {
    private static final Set<String> FLAGS = Set.of("server", "ca", "word", "serve-token", "client-token",
            "name", "target", "listen");

    private Driver() {}

    public static void main(String[] args) {
        if (args.length < 1) {
            exit(2, "usage: driver serve|connect|check|version [flags]");
        }
        String cmd = args[0];
        Map<String, String> flags = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("-")) {
                exit(2, "unexpected argument " + a);
            }
            String k = a.replaceFirst("^--?", "");
            String v;
            int eq = k.indexOf('=');
            if (eq >= 0) {
                v = k.substring(eq + 1);
                k = k.substring(0, eq);
            } else if (i + 1 < args.length) {
                v = args[++i];
            } else {
                exit(2, "flag --" + k + " needs a value");
                return;
            }
            if (!FLAGS.contains(k)) {
                exit(2, "unknown flag --" + k);
            }
            flags.put(k, v);
        }

        Client.Builder b = Client.builder()
                .server(flags.getOrDefault("server", ""))
                .word(flags.get("word"))
                .serveToken(flags.get("serve-token"))
                .clientToken(flags.get("client-token"))
                .name(flags.getOrDefault("name", "conformance"))
                .target(flags.get("target"))
                .agent(Client.DEFAULT_AGENT + " conformance")
                .logger(msg -> System.err.println("pfrelay: " + msg));
        if (flags.containsKey("ca")) {
            b.caFile(Path.of(flags.get("ca")));
        }
        Client c;
        try {
            c = b.build();
        } catch (IllegalArgumentException e) {
            exit(2, e.getMessage());
            return;
        } catch (UncheckedIOException e) {
            exit(1, e.getCause().getMessage());
            return;
        }

        try {
            switch (cmd) {
                case "version": {
                    ServerInfo info = c.probe();
                    System.out.println(info.toJson());
                    exit(0, null);
                    break;
                }
                case "check":
                    c.check();
                    exit(0, null);
                    break;
                case "serve":
                    serve(c, flags.get("target"));
                    break;
                case "connect":
                    connect(c, flags.get("listen"));
                    break;
                default:
                    exit(2, "unknown command " + cmd);
            }
        } catch (ProtoException e) {
            exit(3, e.getMessage());
        } catch (AccessDeniedException e) {
            exit(4, e.getMessage());
        } catch (IOException | RuntimeException e) {
            exit(1, String.valueOf(e.getMessage()));
        }
    }

    /** On SIGTERM: stop, and exit 0. */
    private static void onTerm(Runnable stop) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                stop.run();
            } finally {
                System.out.flush();
                Runtime.getRuntime().halt(0);
            }
        }));
    }

    private static void serve(Client c, String target) throws IOException {
        if (target == null) {
            exit(2, "serve needs --target");
        }
        Listener l = c.listen();
        System.out.println("ready");
        System.out.flush();
        onTerm(l::close);
        while (true) {
            Conn conn;
            try {
                conn = l.accept();
            } catch (IOException e) {
                return;
            }
            new Thread(() -> serveOne(conn, target)).start();
        }
    }

    private static void serveOne(Conn conn, String target) {
        Socket t = new Socket();
        try {
            int colon = target.lastIndexOf(':');
            String host = target.substring(0, colon).replaceAll("^\\[|\\]$", "");
            int port = Integer.parseInt(target.substring(colon + 1));
            t.connect(new InetSocketAddress(host, port), 5000);
        } catch (IOException | RuntimeException e) {
            System.err.println("connection " + conn.id() + ": cannot reach the target: " + e.getMessage());
            conn.fail("the serving side could not reach its target");
            close(t);
            return;
        }
        pipe(t, conn);
    }

    private static void connect(Client c, String listen) throws IOException {
        if (listen == null) {
            exit(2, "connect needs --listen");
        }
        int colon = listen.lastIndexOf(':');
        String host = listen.substring(0, colon).replaceAll("^\\[|\\]$", "");
        int port = Integer.parseInt(listen.substring(colon + 1));
        ServerSocket ss = new ServerSocket();
        ss.bind(new InetSocketAddress(InetAddress.getByName(host), port));
        String bound = ss.getInetAddress().getHostAddress();
        if (bound.contains(":")) {
            bound = "[" + bound + "]";
        }
        System.out.println("listening " + bound + ":" + ss.getLocalPort());
        System.out.flush();
        onTerm(() -> close(ss));
        while (true) {
            Socket local;
            try {
                local = ss.accept();
            } catch (IOException e) {
                return;
            }
            new Thread(() -> {
                Conn conn;
                try {
                    conn = c.dial();
                } catch (IOException e) {
                    System.err.println("dial: " + e.getMessage());
                    close(local);
                    return;
                }
                pipe(local, conn);
            }).start();
        }
    }

    /** Copies both ways, passing half-closes on, until both directions are done or one fails. */
    private static void pipe(Socket local, Conn conn) {
        BlockingQueue<Object> done = new ArrayBlockingQueue<>(2);
        Object ok = new Object();
        new Thread(() -> {
            try {
                copy(local.getInputStream(), conn.getOutputStream());
                conn.shutdownOutput();
                done.add(ok);
            } catch (IOException e) {
                done.add(e);
            }
        }).start();
        new Thread(() -> {
            try {
                copy(conn.getInputStream(), local.getOutputStream());
                local.shutdownOutput();
                done.add(ok);
            } catch (IOException e) {
                done.add(e);
            }
        }).start();
        try {
            for (int i = 0; i < 2; i++) {
                Object r = done.take();
                if (r != ok) {
                    IOException e = (IOException) r;
                    conn.fail(e.getMessage() == null ? e.toString() : e.getMessage());
                    close(local);
                    done.take();
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        conn.close();
        close(local);
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[64 << 10];
        int n;
        while ((n = in.read(buf)) >= 0) {
            out.write(buf, 0, n);
        }
    }

    private static void close(java.io.Closeable c) {
        try {
            c.close();
        } catch (IOException ignored) {
            // done with it
        }
    }

    private static void exit(int code, String msg) {
        if (msg != null) {
            System.err.println(msg);
        }
        System.out.flush();
        System.err.flush();
        Runtime.getRuntime().halt(code);
    }
}
