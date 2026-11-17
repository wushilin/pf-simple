package io.github.wushilin.pfrelay;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * A scriptable hub for the tests: TLS on 127.0.0.1 with a certificate made
 * by the JDK's keytool, HTTP/1.1, and WebSocket upgrades whose server side
 * is the SDK's own WebSocket. Each request goes to the handler on a thread
 * of its own.
 */
final class FakeHub implements AutoCloseable {
    private static final String PASS = "changeit";
    private static Path pem;
    private static SSLContext serverTls;

    /** One request, and the means to answer it. */
    static final class Req {
        final String path; // the whole request path, such as /pf/api/tunnel/serve
        final String endpoint;
        final Map<String, String> headers;
        final long atNanos = System.nanoTime();
        final Socket socket;
        final InputStream in;
        final OutputStream out;

        Req(String path, Map<String, String> headers, Socket socket, InputStream in) throws IOException {
            this.path = path;
            this.endpoint = path.substring(path.lastIndexOf('/') + 1);
            this.headers = headers;
            this.socket = socket;
            this.in = in;
            this.out = socket.getOutputStream();
        }

        boolean isUpgrade() {
            return "websocket".equalsIgnoreCase(headers.get("Upgrade"));
        }

        /** Answers with status and a JSON error (unless 2xx), with the hub's protocol, and closes. */
        void respond(int status, String error) throws IOException {
            String body = error == null ? "" : "{\"error\":" + Json.quote(error) + "}";
            String head = "HTTP/1.1 " + status + " X\r\nX-Pf-Tunnel-Proto: 1\r\nContent-Type: application/json\r\n"
                    + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\nConnection: close\r\n\r\n";
            out.write((head + body).getBytes(StandardCharsets.UTF_8));
            out.flush();
            socket.close();
        }

        /** Answers 101, with extra headers as name, value, ...; returns the hub's side of the WebSocket. */
        WebSocket upgrade(String... extra) throws IOException {
            return upgradeAs(1, extra);
        }

        /** upgrade, answering as a hub that chose protocol proto. */
        WebSocket upgradeAs(int proto, String... extra) throws IOException {
            StringBuilder b = new StringBuilder("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    + "Connection: Upgrade\r\nX-Pf-Tunnel-Proto: " + proto + "\r\nSec-WebSocket-Accept: "
                    + Http.accept(headers.get("Sec-WebSocket-Key")) + "\r\n");
            for (int i = 0; i < extra.length; i += 2) {
                b.append(extra[i]).append(": ").append(extra[i + 1]).append("\r\n");
            }
            out.write(b.append("\r\n").toString().getBytes(StandardCharsets.UTF_8));
            out.flush();
            return new WebSocket(socket, socket, in, out, false, null);
        }
    }

    interface Handler {
        void handle(Req r) throws Exception;
    }

    private final SSLServerSocket server;
    private final Handler handler;
    final List<Req> requests = new CopyOnWriteArrayList<>();

    FakeHub(Handler handler) throws Exception {
        this.handler = handler;
        server = (SSLServerSocket) tls().getServerSocketFactory().createServerSocket(0, 200,
                InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(this::acceptLoop, "fake-hub");
        t.setDaemon(true);
        t.start();
    }

    String url() {
        return "https://127.0.0.1:" + server.getLocalPort();
    }

    /** A client of this hub, trusting its certificate. */
    Client.Builder client() throws Exception {
        tls();
        return Client.builder().server(url()).caFile(pem).word("aaaa-bbbb-cccc").name("test tunnel")
                .serveToken("s".repeat(32));
    }

    /** Requests to endpoint so far. */
    List<Req> requests(String endpoint) {
        return requests.stream().filter(r -> r.endpoint.equals(endpoint)).collect(java.util.stream.Collectors.toList());
    }

    private void acceptLoop() {
        while (true) {
            Socket s;
            try {
                s = server.accept();
            } catch (IOException e) {
                return;
            }
            Thread t = new Thread(() -> serveOne(s));
            t.setDaemon(true);
            t.start();
        }
    }

    private void serveOne(Socket s) {
        try {
            InputStream in = new BufferedInputStream(s.getInputStream());
            String line = readLine(in);
            String[] parts = line.split(" ");
            String path = parts.length > 1 ? parts[1] : "";
            Map<String, String> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (String l = readLine(in); !l.isEmpty(); l = readLine(in)) {
                int colon = l.indexOf(':');
                h.put(l.substring(0, colon).trim(), l.substring(colon + 1).trim());
            }
            Req r = new Req(path, h, s, in);
            requests.add(r);
            handler.handle(r);
        } catch (Exception e) {
            try {
                s.close();
            } catch (IOException ignored) {
                // done
            }
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (int c = in.read(); c != '\n'; c = in.read()) {
            if (c < 0) {
                throw new EOFException();
            }
            if (c != '\r') {
                b.write(c);
            }
        }
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    @Override
    public void close() throws IOException {
        server.close();
    }

    /** Reads frames on the hub's side of a WebSocket until text arrives; pings and pongs are skipped. */
    static String nextText(WebSocket ws) throws IOException {
        while (true) {
            WebSocket.Frame f = ws.readHeader();
            byte[] p = ws.readPayload(f, 1 << 20);
            if (f.op == WebSocket.OP_TEXT) {
                return new String(p, StandardCharsets.UTF_8);
            }
            if (f.op == WebSocket.OP_CLOSE) {
                throw new EOFException("closed");
            }
        }
    }

    /** Holds a control channel open, answering pings, until it ends. */
    static void hold(WebSocket ws) {
        try {
            while (true) {
                WebSocket.Frame f = ws.readHeader();
                byte[] p = ws.readPayload(f, 4096);
                if (f.op == WebSocket.OP_CLOSE) {
                    return;
                }
                if (f.op == WebSocket.OP_PING) {
                    ws.writeFrame(WebSocket.OP_PONG, p);
                }
            }
        } catch (IOException e) {
            // gone
        }
    }

    private static synchronized SSLContext tls() throws Exception {
        if (serverTls != null) {
            return serverTls;
        }
        Path dir = Files.createTempDirectory("pfrelay-test");
        dir.toFile().deleteOnExit();
        Path ks = dir.resolve("hub.p12");
        pem = dir.resolve("hub.pem");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        run(keytool, "-genkeypair", "-alias", "hub", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=127.0.0.1", "-ext", "san=ip:127.0.0.1", "-validity", "2",
                "-keystore", ks.toString(), "-storetype", "PKCS12", "-storepass", PASS, "-keypass", PASS);
        run(keytool, "-exportcert", "-rfc", "-alias", "hub", "-keystore", ks.toString(), "-storepass", PASS,
                "-file", pem.toString());
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) {
            store.load(in, PASS.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, PASS.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        ks.toFile().deleteOnExit();
        pem.toFile().deleteOnExit();
        serverTls = ctx;
        return ctx;
    }

    private static void run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IOException("keytool failed: " + out);
        }
    }
}
