package io.github.wushilin.pfrelay.conformance;

import io.github.wushilin.pfrelay.AccessDeniedException;
import io.github.wushilin.pfrelay.Client;
import io.github.wushilin.pfrelay.ClientEvents;
import io.github.wushilin.pfrelay.Conn;
import io.github.wushilin.pfrelay.ConnId;
import io.github.wushilin.pfrelay.ConnInfo;
import io.github.wushilin.pfrelay.Forwarder;
import io.github.wushilin.pfrelay.Listener;
import io.github.wushilin.pfrelay.Proto;
import io.github.wushilin.pfrelay.ProtoException;
import io.github.wushilin.pfrelay.ServerInfo;
import io.github.wushilin.pfrelay.Side;
import io.github.wushilin.pfrelay.Stats;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/**
 * The Java SDK's conformance driver: the small program the conformance
 * suite runs to put the SDK through its cases (conformance/README.md). It
 * uses only the SDK's public API, as an application would.
 */
public final class Driver {
    /** What the suite asks the driver to do. */
    enum Command {
        SERVE, CONNECT, CHECK, VERSION,
        /** Prints the range of tunnel protocols the driver speaks. */
        PROTOCOLS;

        String wire() {
            return name().toLowerCase(Locale.ROOT);
        }

        static Optional<Command> parse(String s) {
            for (Command c : values()) {
                if (c.wire().equals(s)) {
                    return Optional.of(c);
                }
            }
            return Optional.empty();
        }
    }

    /** Which part of the SDK carries connections. */
    enum Mode {
        /** The SDK's listen/accept and dial API, with the driver's own copy loop. */
        LISTEN,
        /** The SDK's forwarders: serve(target) and connect(listener). */
        FORWARD;

        String wire() {
            return name().toLowerCase(Locale.ROOT);
        }

        static Optional<Mode> parse(String s) {
            for (Mode m : values()) {
                if (m.wire().equals(s)) {
                    return Optional.of(m);
                }
            }
            return Optional.empty();
        }
    }

    /** The command line's flags. */
    enum Flag {
        SERVER("server"), CA("ca"), WORD("word"), SERVE_TOKEN("serve-token"), CLIENT_TOKEN("client-token"),
        NAME("name"), TARGET("target"), LISTEN("listen"), MODE("mode"), NO_ACCEPT("no-accept", false),
        /** The newest protocol to offer; 0: announce none, like a client from before 0.14. */
        PROTO_MAX("proto-max");

        final String wire;
        final boolean takesValue;

        Flag(String wire) {
            this(wire, true);
        }

        Flag(String wire, boolean takesValue) {
            this.wire = wire;
            this.takesValue = takesValue;
        }

        static Optional<Flag> parse(String s) {
            for (Flag f : values()) {
                if (f.wire.equals(s)) {
                    return Optional.of(f);
                }
            }
            return Optional.empty();
        }
    }

    /** A question the suite asks on stdin while serve or connect runs. */
    enum Query {
        STATS, CONNS, /** "drop <id>": drop that connection. */ DROP;

        String wire() {
            return name().toLowerCase(Locale.ROOT);
        }

        static Optional<Query> parse(String s) {
            for (Query q : values()) {
                if (q.wire().equals(s)) {
                    return Optional.of(q);
                }
            }
            return Optional.empty();
        }
    }

    /** A line the driver prints when the SDK reports one of its events. */
    enum Event {
        READY("ready"), // the first registration (serve)
        LISTENING("listening"), // "listening HOST:PORT" (connect)
        OPENED("opened"), // "opened <id> <side>"
        CLOSED("closed"), // "closed <id> <sent> <received> ok|failed"
        REFUSED("refused"), // "refused <id>"
        TUNNEL_UP("tunnel up"), // watch: reachable (connect)
        TUNNEL_DOWN("tunnel down");

        final String wire;

        Event(String wire) {
            this.wire = wire;
        }
    }

    /** How a closed connection ended, in {@link Event#CLOSED}. */
    enum Outcome {
        OK, FAILED;

        String wire() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** The exit codes of conformance/README.md. */
    enum Exit {
        OK(0), FAILURE(1), USAGE(2), PROTO(3), DENIED(4);

        final int code;

        Exit(int code) {
            this.code = code;
        }
    }

    /** The answer to {@link Query#STATS}. */
    record StatsAnswer(long opened, long active, long failed, long sent, long received) {
        static StatsAnswer of(Stats s) {
            return new StatsAnswer(s.opened(), s.active(), s.failed(), s.sent(), s.received());
        }

        String toJson() {
            return "{\"opened\":" + opened + ",\"active\":" + active + ",\"failed\":" + failed + ",\"sent\":" + sent
                    + ",\"received\":" + received + "}";
        }
    }

    /** One entry of the answer to {@link Query#CONNS}. */
    record ConnAnswer(String id, Side side, long sent, long received) {
        static ConnAnswer of(ConnInfo ci) {
            return new ConnAnswer(ci.id().toString(), ci.side(), ci.sent(), ci.received());
        }

        String toJson() {
            return "{\"id\":" + quote(id) + ",\"side\":" + quote(side.toString()) + ",\"sent\":" + sent
                    + ",\"received\":" + received + "}";
        }
    }

    static final String DROP_REASON = "dropped by the conformance suite";
    static final String UNREACHABLE = "the serving side could not reach its target";
    static final String DEFAULT_NAME = "conformance";

    private Driver() {}

    public static void main(String[] args) {
        if (args.length < 1) {
            exit(Exit.USAGE, "usage: driver serve|connect|check|version [flags]");
        }
        Command cmd = Command.parse(args[0]).orElse(null);
        if (cmd == null) {
            exit(Exit.USAGE, "unknown command " + args[0]);
            return;
        }
        Map<Flag, String> flags = new EnumMap<>(Flag.class);
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("-")) {
                exit(Exit.USAGE, "unexpected argument " + a);
            }
            String k = a.replaceFirst("^--?", "");
            String v = null;
            int eq = k.indexOf('=');
            if (eq >= 0) {
                v = k.substring(eq + 1);
                k = k.substring(0, eq);
            }
            Flag f = Flag.parse(k).orElse(null);
            if (f == null) {
                exit(Exit.USAGE, "unknown flag --" + k);
                return;
            }
            if (v == null) {
                if (!f.takesValue) {
                    v = Boolean.TRUE.toString();
                } else if (i + 1 < args.length) {
                    v = args[++i];
                } else {
                    exit(Exit.USAGE, "flag --" + k + " needs a value");
                }
            }
            flags.put(f, v);
        }
        if (cmd == Command.PROTOCOLS) {
            say(Proto.range(Proto.MIN, Proto.MAX));
            exit(Exit.OK, null);
        }
        int protoMax = Proto.MAX;
        try {
            protoMax = Integer.parseInt(flags.getOrDefault(Flag.PROTO_MAX, Integer.toString(Proto.MAX)));
        } catch (NumberFormatException e) {
            protoMax = -1;
        }
        if (protoMax < 0 || protoMax > Proto.MAX) {
            exit(Exit.USAGE, "--proto-max must be from 0 to " + Proto.MAX);
        }
        Mode mode = Mode.parse(flags.getOrDefault(Flag.MODE, Mode.LISTEN.wire())).orElse(null);
        if (mode == null) {
            exit(Exit.USAGE, "unknown mode " + flags.get(Flag.MODE));
            return;
        }
        boolean noAccept = Boolean.parseBoolean(flags.getOrDefault(Flag.NO_ACCEPT, Boolean.FALSE.toString()));

        AtomicBoolean ready = new AtomicBoolean();
        ClientEvents events = new ClientEvents() {
            @Override
            public void onServing(boolean up) {
                if (up && ready.compareAndSet(false, true)) {
                    say(Event.READY.wire);
                }
            }

            @Override
            public void onTunnel(boolean up, IOException error) {
                say((up ? Event.TUNNEL_UP : Event.TUNNEL_DOWN).wire);
            }

            @Override
            public void onOpen(ConnInfo ci) {
                say(Event.OPENED.wire + " " + ci.id() + " " + ci.side());
            }

            @Override
            public void onClose(ConnInfo ci, IOException error) {
                Outcome o = error == null ? Outcome.OK : Outcome.FAILED;
                say(Event.CLOSED.wire + " " + ci.id() + " " + ci.sent() + " " + ci.received() + " " + o.wire());
            }

            @Override
            public void onRefuse(ConnId id, String reason) {
                say(Event.REFUSED.wire + " " + id);
            }
        };

        Client.Builder b = Client.builder()
                .server(flags.getOrDefault(Flag.SERVER, ""))
                .word(flags.get(Flag.WORD))
                .serveToken(flags.get(Flag.SERVE_TOKEN))
                .clientToken(flags.get(Flag.CLIENT_TOKEN))
                .name(flags.getOrDefault(Flag.NAME, DEFAULT_NAME))
                .target(flags.get(Flag.TARGET))
                .agent(Client.DEFAULT_AGENT + " conformance")
                .events(events)
                .maxProto(protoMax == 0 ? -1 : protoMax) // 0: announce no protocol at all
                .logger(msg -> System.err.println("pfrelay: " + msg));
        if (flags.containsKey(Flag.CA)) {
            b.caFile(Path.of(flags.get(Flag.CA)));
        }
        Client c;
        try {
            c = b.build();
        } catch (IllegalArgumentException e) {
            exit(Exit.USAGE, e.getMessage());
            return;
        } catch (UncheckedIOException e) {
            exit(Exit.FAILURE, e.getCause().getMessage());
            return;
        }

        try {
            switch (cmd) {
                case VERSION: {
                    ServerInfo info = c.probe();
                    say(info.toJson());
                    exit(Exit.OK, null);
                    break;
                }
                case CHECK:
                    c.check();
                    exit(Exit.OK, null);
                    break;
                case SERVE:
                    startQueries(c);
                    serve(c, need(flags, Flag.TARGET), mode, noAccept);
                    break;
                case CONNECT:
                    startQueries(c);
                    connect(c, need(flags, Flag.LISTEN), mode);
                    break;
                default:
                    exit(Exit.USAGE, "unknown command " + cmd);
            }
        } catch (ProtoException e) {
            exit(Exit.PROTO, e.getMessage());
        } catch (AccessDeniedException e) {
            exit(Exit.DENIED, e.getMessage());
        } catch (IOException | RuntimeException e) {
            exit(Exit.FAILURE, String.valueOf(e.getMessage()));
        }
    }

    private static String need(Map<Flag, String> flags, Flag f) {
        String v = flags.get(f);
        if (v == null) {
            exit(Exit.USAGE, "this command needs --" + f.wire);
        }
        return v;
    }

    /** On SIGTERM: stop, and exit 0. */
    private static void onTerm(Runnable stop) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                stop.run();
            } finally {
                System.out.flush();
                Runtime.getRuntime().halt(Exit.OK.code);
            }
        }));
    }

    private static void waitForever() {
        try {
            new CountDownLatch(1).await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void serve(Client c, String target, Mode mode, boolean noAccept) throws IOException {
        if (mode == Mode.FORWARD) {
            Forwarder f = c.serve(target); // its registration says ready
            onTerm(f::close);
            waitForever();
            return;
        }
        Listener l = c.listen(); // its registration says ready
        onTerm(l::close);
        if (noAccept) {
            waitForever();
            return;
        }
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
            InetSocketAddress a = hostPort(target);
            t.connect(new InetSocketAddress(a.getHostString(), a.getPort()), 5000);
        } catch (IOException | RuntimeException e) {
            System.err.println("connection " + conn.id() + ": cannot reach the target: " + e.getMessage());
            conn.fail(UNREACHABLE);
            close(t);
            return;
        }
        pipe(t, conn);
    }

    private static InetSocketAddress hostPort(String s) {
        int colon = s.lastIndexOf(':');
        if (colon <= 0) {
            throw new IllegalArgumentException("not host:port: " + s);
        }
        String host = s.substring(0, colon).replaceAll("^\\[|\\]$", "");
        return InetSocketAddress.createUnresolved(host, Integer.parseInt(s.substring(colon + 1)));
    }

    private static void connect(Client c, String listen, Mode mode) throws IOException {
        InetSocketAddress want = hostPort(listen);
        ServerSocket ss = new ServerSocket();
        ss.bind(new InetSocketAddress(InetAddress.getByName(want.getHostString()), want.getPort()));
        String bound = ss.getInetAddress().getHostAddress();
        if (bound.contains(":")) {
            bound = "[" + bound + "]";
        }
        say(Event.LISTENING.wire + " " + bound + ":" + ss.getLocalPort());
        c.watch();
        if (mode == Mode.FORWARD) {
            Forwarder f = c.connect(ss);
            onTerm(f::close);
            waitForever();
            return;
        }
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
        BlockingQueue<Optional<IOException>> done = new ArrayBlockingQueue<>(2);
        new Thread(() -> {
            try {
                copy(local.getInputStream(), conn.getOutputStream());
                conn.shutdownOutput();
                done.add(Optional.empty());
            } catch (IOException e) {
                done.add(Optional.of(e));
            }
        }).start();
        new Thread(() -> {
            try {
                copy(conn.getInputStream(), local.getOutputStream());
                local.shutdownOutput();
                done.add(Optional.empty());
            } catch (IOException e) {
                done.add(Optional.of(e));
            }
        }).start();
        try {
            for (int i = 0; i < 2; i++) {
                Optional<IOException> r = done.take();
                if (r.isPresent()) {
                    IOException e = r.get();
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

    // ---------- queries ----------

    private static void startQueries(Client c) {
        Thread t = new Thread(() -> queries(c), "queries");
        t.setDaemon(true);
        t.start();
    }

    /** Answers the suite's questions on stdin. */
    private static void queries(Client c) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                String[] parts = line.strip().split(" ", 2);
                Query q = Query.parse(parts[0]).orElse(null);
                if (q == null) {
                    continue;
                }
                String arg = parts.length > 1 ? parts[1].strip() : "";
                String answer;
                switch (q) {
                    case STATS:
                        answer = StatsAnswer.of(c.stats()).toJson();
                        break;
                    case CONNS: {
                        List<ConnAnswer> list = c.conns().stream().map(ConnAnswer::of).collect(Collectors.toList());
                        answer = list.stream().map(ConnAnswer::toJson).collect(Collectors.joining(",", "[", "]"));
                        break;
                    }
                    case DROP:
                        answer = Boolean.toString(dropByName(c, arg));
                        break;
                    default:
                        continue;
                }
                say(q.wire() + " " + answer);
            }
        } catch (IOException e) {
            System.err.println("reading queries: " + e.getMessage());
        }
    }

    /** Drops the open connection whose id prints as name. */
    private static boolean dropByName(Client c, String name) {
        for (ConnInfo ci : c.conns()) {
            if (ci.id().toString().equals(name)) {
                return c.drop(ci.id(), DROP_REASON);
            }
        }
        return false;
    }

    // ---------- output ----------

    /** Prints one line of output; lines never interleave. */
    private static synchronized void say(String line) {
        System.out.println(line);
        System.out.flush();
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            if (ch == '"' || ch == '\\') {
                b.append('\\').append(ch);
            } else if (ch < 0x20) {
                b.append(String.format("\\u%04x", (int) ch));
            } else {
                b.append(ch);
            }
        }
        return b.append('"').toString();
    }

    private static void close(java.io.Closeable c) {
        try {
            c.close();
        } catch (IOException ignored) {
            // done with it
        }
    }

    private static void exit(Exit code, String msg) {
        if (msg != null) {
            System.err.println(msg);
        }
        System.out.flush();
        System.err.flush();
        Runtime.getRuntime().halt(code.code);
    }
}
