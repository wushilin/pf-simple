package io.github.wushilin.pfrelayquic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

/**
 * The SDK's unit tests, as a plain main class (no test framework): every
 * static method whose name starts with "test" runs. What crosses a real hub
 * is the conformance suite's (conformance/README.md).
 */
public final class TestMain {
    // A throwaway self-signed ECDSA P-256 certificate, its key, and a key that is not its own.
    static final String CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBpDCCAUqgAwIBAgIUCl5LIPUOTnjxq6Ow4G0A648cTSIwCgYIKoZIzj0EAwIw\n"
            + "HjEcMBoGA1UEAwwTcGYtc2ltcGxlIHJlbGF5IGh1YjAgFw0yNjExMTUxMzU4MjZa\n"
            + "GA8yMTI2MTAyMjEzNTgyNlowHjEcMBoGA1UEAwwTcGYtc2ltcGxlIHJlbGF5IGh1\n"
            + "YjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAC/FRQdsqncgOdJDnVjvQ9vyFUm\n"
            + "ZpudAsHPHWo4xHrogJzqeb6I5d6C+qda2e3ICtkVkWaIbshq8tPVAsVJpwmjZDBi\n"
            + "MB0GA1UdDgQWBBTNlglFunTwoOG3O7weI7nKopdMnzAfBgNVHSMEGDAWgBTNlglF\n"
            + "unTwoOG3O7weI7nKopdMnzAPBgNVHRMBAf8EBTADAQH/MA8GA1UdEQQIMAaHBH8A\n"
            + "AAEwCgYIKoZIzj0EAwIDSAAwRQIgUbCgNMza5SuYkuxFWLmIo/BwT9CZi8DKiLva\n"
            + "AvERqKwCIQDDDAUoXc0MQr4XGUnHAI+zsA4w9f8XiuZQX7MIC3c9rA==\n"
            + "-----END CERTIFICATE-----\n";
    static final String CERT_SHA256 = "7b786759e06d1f0eba39283421aca146b2c6fe1b04ac646966234a1e0f70ed64";
    static final String KEY = "-----BEGIN PRIVATE KEY-----\n"
            + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgz+W0AQaMAAbkfr9Q\n"
            + "vEQpRfiIMnyqWyyjVQyDMVeBhp2hRANCAAQAvxUUHbKp3IDnSQ51Y70Pb8hVJmab\n"
            + "nQLBzx1qOMR66ICc6nm+iOXegvqnWtntyArZFZFmiG7IavLT1QLFSacJ\n"
            + "-----END PRIVATE KEY-----\n";
    static final String OTHER_KEY = "-----BEGIN PRIVATE KEY-----\n"
            + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpSGLhJo/GevixBHH\n"
            + "nEv+mVOZJXRB+O0Cn7dGTy6MF2WhRANCAAQd7yhaCchlFM2BQ0HLayqhTMDSLA63\n"
            + "SC9sU4glgWB1W3X9PvxMXx+g2TvL3p/StNmkhf4OBq+8doz4feoSxzSn\n"
            + "-----END PRIVATE KEY-----\n";
    static final String OTHER_SHA256 = "00".repeat(32);

    private TestMain() {}

    public static void main(String[] args) throws Exception {
        System.setProperty("tech.kwik.core.no-security-warnings", "true");
        List<Method> tests = new ArrayList<>();
        for (Method m : TestMain.class.getDeclaredMethods()) {
            if (m.getName().startsWith("test") && Modifier.isStatic(m.getModifiers())
                    && (args.length == 0 || java.util.Arrays.stream(args).anyMatch(a -> m.getName().contains(a)))) {
                tests.add(m);
            }
        }
        tests.sort((a, b) -> a.getName().compareTo(b.getName()));
        int failed = 0;
        for (Method m : tests) {
            long t0 = System.nanoTime();
            try {
                m.invoke(null);
                System.out.printf("ok    %s (%d ms)%n", m.getName(), (System.nanoTime() - t0) / 1_000_000);
            } catch (InvocationTargetException e) {
                failed++;
                System.out.printf("FAIL  %s: %s%n", m.getName(), e.getCause());
                e.getCause().printStackTrace(System.out);
            }
        }
        System.out.println(tests.size() + " tests, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void check(boolean ok, String what) {
        if (!ok) {
            throw new AssertionError(what);
        }
    }

    interface Body {
        void run() throws Exception;
    }

    static <T extends Throwable> T expect(Class<T> type, Body b) throws Exception {
        try {
            b.run();
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                return type.cast(t);
            }
            throw new AssertionError("expected " + type.getSimpleName() + ", got " + t, t);
        }
        throw new AssertionError("expected " + type.getSimpleName() + ", got nothing");
    }

    static InputStream in(byte[] b) {
        return new ByteArrayInputStream(b);
    }

    // ---------- the message envelope (§13.4) ----------

    static void testMessageRoundTrip() throws Exception {
        String json = new Wire.Obj().put("op", "serve").put("proto", "3").put("name", "Büro \"SSH\"")
                .put("serveToken", "").put("status", 200).toString();
        check(!json.contains("serveToken"), "empty strings are left out: " + json);
        byte[] b = Wire.encode(json);
        int len = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
        check(len == b.length - 2, "the length is big-endian, of the UTF-8 bytes");
        ByteArrayOutputStream two = new ByteArrayOutputStream();
        two.write(b);
        two.write(new byte[] {0x00, 0x00, 0x02, 'h', 'i'}); // a data frame after it
        InputStream s = in(two.toByteArray());
        Map<String, Object> m = Wire.read(s);
        check("serve".equals(m.get("op")) && "Büro \"SSH\"".equals(m.get("name")), "fields: " + m);
        check(Wire.num(m, "status") == 200, "a number");
        check(s.available() == 5, "nothing after the message is read");
    }

    static void testMessageLimits() throws Exception {
        String big = new Wire.Obj().put("x", "a".repeat(4096)).toString();
        expect(Wire.MessageException.class, () -> Wire.encode(big));
        String fits = new Wire.Obj().put("x", "a".repeat(4096 - 8)).toString();
        check(Wire.encode(fits).length == 4098, "4096 bytes is allowed");
        expect(Wire.MessageException.class, () -> Wire.read(in(new byte[] {0x10, 0x01}))); // 4097
        expect(Wire.MessageException.class, () -> Wire.read(in(new byte[] {0x00}))); // cut in the length
        expect(Wire.MessageException.class, () -> Wire.read(in(new byte[] {0x00, 0x05, '{', '}'}))); // cut short
        expect(Wire.MessageException.class, () -> Wire.read(in(Wire.encode("[1]")))); // not an object
        expect(Wire.MessageException.class, () -> Wire.read(in(Wire.encode("{\"a\":")))); // not JSON
        check(Wire.read(in(new byte[0])) == null, "a FIN before the message");
        check(Wire.read(in(Wire.encode("{\"end\":\"takeover\",\"new\":[1,{}]}"))).get("end").equals("takeover"),
                "unknown fields are ignored");
    }

    static void testReasonsToTheHub() {
        check(Wire.ascii("café\nnope\u0007!", 128).equals("cafnope!"), "printable ASCII only");
        check(Wire.ascii("x".repeat(300), 128).length() == 128, "cut to 128");
        check(QuicTransport.codeName(5L).equals("cancelled") && QuicTransport.codeName(99L).equals("broken"),
                "an unknown code means broken");
    }

    // ---------- discovery (§13.2) ----------

    static void testDiscovery() throws Exception {
        String fp = CERT_SHA256;
        Discovery d = Discovery.parse("{\"host\":\"gate.example.net\",\"port\":443,\"fingerprints\":[\"" + fp
                + "\"],\"later\":true}");
        check(d.host().equals("gate.example.net") && d.port() == 443 && d.fingerprints().equals(List.of(fp)),
                "parsed: " + d);
        check(!d.hostIsIp(), "a DNS name");
        check(Discovery.parse("{\"host\":\"2001:db8::1\",\"port\":1,\"fingerprints\":[\"" + fp + "\"]}").hostIsIp(),
                "IPv6, without brackets");
        check(Discovery.parse("{\"host\":\"127.0.0.1\",\"port\":65535,\"fingerprints\":[\"" + fp + "\",\"" + fp
                + "\"]}").hostIsIp(), "IPv4, two fingerprints");
        for (String bad : new String[] {
            "{\"host\":\"h\",\"port\":0,\"fingerprints\":[\"" + fp + "\"]}",
            "{\"host\":\"h\",\"port\":65536,\"fingerprints\":[\"" + fp + "\"]}",
            "{\"host\":\"h\",\"port\":1.5,\"fingerprints\":[\"" + fp + "\"]}",
            "{\"host\":\"[::1]\",\"port\":1,\"fingerprints\":[\"" + fp + "\"]}",
            "{\"host\":\"\",\"port\":1,\"fingerprints\":[\"" + fp + "\"]}",
            "{\"host\":\"h\",\"port\":1,\"fingerprints\":[]}",
            "{\"host\":\"h\",\"port\":1,\"fingerprints\":[\"" + fp + "\",\"" + fp + "\",\"" + fp + "\",\"" + fp
                    + "\",\"" + fp + "\"]}",
            "{\"host\":\"h\",\"port\":1,\"fingerprints\":[\"abc\"]}",
            "{\"host\":\"h\",\"port\":1}",
            "not json",
        }) {
            expect(IOException.class, () -> Discovery.parse(bad));
        }
    }

    // ---------- pinning (§13.3) ----------

    static X509Certificate cert() throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(in(CERT.getBytes(StandardCharsets.US_ASCII)));
    }

    static void testPinTrustManager() throws Exception {
        X509Certificate c = cert();
        check(Pin.fingerprint(c.getEncoded()).equals(CERT_SHA256), "the SHA-256 of the DER");
        Pin ok = new Pin(List.of(OTHER_SHA256, CERT_SHA256.toUpperCase(java.util.Locale.ROOT)));
        ok.checkServerTrusted(new X509Certificate[] {c}, "ECDHE");
        check(!ok.mismatched(), "a pinned certificate is taken, whatever its chain, name or dates");
        Pin bad = new Pin(List.of(OTHER_SHA256));
        expect(CertificateException.class, () -> bad.checkServerTrusted(new X509Certificate[] {c}, "ECDHE"));
        check(bad.mismatched(), "a mismatch is recorded");
        expect(CertificateException.class, () -> new Pin(List.of(CERT_SHA256)).checkServerTrusted(new X509Certificate[0], ""));
    }

    /** A kwik QUIC server on 127.0.0.1 with ALPN pf-tunnel, presenting CERT with the given key. */
    static final class Server implements AutoCloseable {
        final ServerConnector connector;
        final int port;
        /** What the server does with a stream the client opens; nothing by default. */
        volatile java.util.function.Consumer<QuicStream> onStream = s -> {};
        /** The server's side of the last connection. */
        volatile QuicConnection peer;

        Server(String key) throws Exception {
            this(key, QuicConnection.QuicVersion.V1);
        }

        Server(String key, QuicConnection.QuicVersion version) throws Exception {
            String b64 = key.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            java.security.PrivateKey pk = java.security.KeyFactory.getInstance("EC")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(b64)));
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            char[] pw = "test".toCharArray();
            ks.setKeyEntry("hub", pk, pw, new java.security.cert.Certificate[] {cert()});
            DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            port = socket.getLocalPort();
            ServerConnector.Builder builder = ServerConnector.builder();
            // kwik's builder starts with version 1 and only adds to it
            setField(builder, "supportedVersions", new ArrayList<>(List.of(version)));
            connector = builder
                    .withSocket(socket)
                    .withKeyStore(ks, "hub", pw, "secp256r1")
                    .withLogger(new tech.kwik.core.log.NullLogger())
                    .withSupportedVersion(version)
                    .withConfiguration(ServerConnectionConfig.builder()
                            .maxIdleTimeoutInSeconds(30)
                            .maxOpenPeerInitiatedBidirectionalStreams(200)
                            .maxOpenPeerInitiatedUnidirectionalStreams(0)
                            .maxConnectionBufferSize(4 << 20)
                            .maxBidirectionalStreamBufferSize(64 << 10)
                            .build())
                    .build();
            connector.registerApplicationProtocol(Wire.ALPN, new ApplicationProtocolConnectionFactory() {
                @Override
                public ApplicationProtocolConnection createConnection(String protocol, QuicConnection c) {
                    peer = c;
                    return new ApplicationProtocolConnection() {
                        @Override
                        public void acceptPeerInitiatedStream(QuicStream s) {
                            Thread t = new Thread(() -> onStream.accept(s), "test-hub");
                            t.setDaemon(true);
                            t.start();
                        }
                    };
                }
            });
            connector.start();
        }

        /** The server's side of the connection, once the server has it. */
        QuicConnection peer() throws InterruptedException {
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (peer == null && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            check(peer != null, "the server has the connection");
            return peer;
        }

        Discovery discovery(String fingerprint) {
            return new Discovery("127.0.0.1", port, List.of(fingerprint));
        }

        @Override
        public void close() {
            connector.close();
        }
    }

    static void testHandshakeWithThePinnedCertificate() throws Exception {
        try (Server s = new Server(KEY)) {
            Pin pin = new Pin(List.of(CERT_SHA256));
            QuicTransport.QConn qc = new QuicTransport().dial(s.discovery(CERT_SHA256), pin);
            check(qc.alive() && !pin.mismatched(), "connected");
            qc.close(Wire.CODE_NONE, "done");
        }
    }

    static void testHandshakeWithAnotherCertificate() throws Exception {
        try (Server s = new Server(KEY)) {
            Pin pin = new Pin(List.of(OTHER_SHA256));
            expect(IOException.class, () -> new QuicTransport().dial(s.discovery(OTHER_SHA256), pin));
            check(pin.mismatched(), "refused for the pin");
        }
    }

    /**
     * A server that presents the pinned certificate without holding its key
     * fails the handshake: the CertificateVerify signature is still checked.
     */
    static void testHandshakeSignatureIsVerified() throws Exception {
        try (Server s = new Server(OTHER_KEY)) {
            Pin pin = new Pin(List.of(CERT_SHA256));
            expect(IOException.class, () -> new QuicTransport().dial(s.discovery(CERT_SHA256), pin));
            check(!pin.mismatched(), "refused before the pin was even asked");
        }
    }

    // ---------- with a test hub (a kwik server) ----------

    static QuicTransport.QConn connect(Server s) throws IOException {
        return new QuicTransport().dial(s.discovery(CERT_SHA256), new Pin(List.of(CERT_SHA256)));
    }

    static Object field(Object o, String name) throws Exception {
        for (Class<?> k = o.getClass(); k != null; k = k.getSuperclass()) {
            try {
                java.lang.reflect.Field f = k.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(o);
            } catch (NoSuchFieldException e) {
                // look in the superclass
            }
        }
        throw new NoSuchFieldException(name);
    }

    static void setField(Object o, String name, Object v) throws Exception {
        java.lang.reflect.Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(o, v);
    }

    /** A transport whose connection to the test hub is made already, and the Params of a request. */
    static final class Rig implements AutoCloseable {
        final Server hub;
        final QuicTransport t = new QuicTransport();
        final QuicTransport.QConn qc;
        final io.github.wushilin.pfrelay.Transport.Params p;

        Rig() throws Exception {
            hub = new Server(KEY);
            qc = t.dial(hub.discovery(CERT_SHA256), new Pin(List.of(CERT_SHA256)));
            setField(t, "conn", qc);
            io.github.wushilin.pfrelay.Client c = QuicClient.builder().server("https://127.0.0.1:1")
                    .word("aaaa-bbbb-cccc").serveToken("serve-token-0123456789abcdefghijkl").logger(m -> {}).build();
            Class<?> canceller = Class.forName("io.github.wushilin.pfrelay.Canceller");
            java.lang.reflect.Constructor<io.github.wushilin.pfrelay.Transport.Params> k =
                    io.github.wushilin.pfrelay.Transport.Params.class.getDeclaredConstructor(
                            io.github.wushilin.pfrelay.Client.class, canceller);
            k.setAccessible(true);
            p = k.newInstance(c, null);
        }

        /** The hub answers every request with answer, then FIN and STOP_SENDING (refused) when it refuses. */
        void answer(String answer) {
            hub.onStream = s -> {
                try {
                    Wire.read(s.getInputStream());
                    Wire.write(s.getOutputStream(), answer);
                    int status = Wire.num(Json.parseObject(answer), "status");
                    if (status == 204) {
                        s.getOutputStream().close(); // check: FIN after the answer
                    } else if (status != 200) {
                        s.getOutputStream().close();
                        s.abortReading(Wire.CODE_REFUSED);
                    }
                } catch (IOException | RuntimeException ignored) {
                    // the client went
                }
            };
        }

        @Override
        public void close() {
            qc.close(Wire.CODE_NONE, "done");
            hub.close();
        }
    }

    /**
     * kwik wakes a writer blocked on flow control by interrupting it when
     * the stream is reset, and may leave the interrupt set. The write fails
     * with a plain IOException, and the thread is not left interrupted.
     */
    static void testResetDuringABlockedWriteLeavesNoInterrupt() throws Exception {
        try (Server s = new Server(KEY)) {
            s.onStream = st -> {
                try {
                    Thread.sleep(100); // let the client block
                } catch (InterruptedException e) {
                    return;
                }
                st.abortReading(Wire.CODE_CANCELLED); // STOP_SENDING: kwik resets the client's direction
                st.resetStream(Wire.CODE_CANCELLED);
            };
            QuicTransport.QConn qc = connect(s);
            try {
                int interrupted = 0;
                int interruptedIO = 0;
                byte[] chunk = new byte[16 << 10];
                for (int round = 0; round < 30; round++) {
                    QStream q = new QStream(qc.c.createStream(true));
                    IOException failed = null;
                    try {
                        for (int i = 0; i < 100_000; i++) {
                            q.output().write(chunk);
                        }
                    } catch (IOException e) {
                        failed = e;
                    }
                    check(failed != null, "the write fails");
                    if (failed instanceof java.io.InterruptedIOException) {
                        interruptedIO++;
                    }
                    if (Thread.interrupted()) {
                        interrupted++;
                    }
                }
                check(interrupted == 0 && interruptedIO == 0, "of 30 writes failed by a reset, " + interruptedIO
                        + " threw InterruptedIOException, and " + interrupted + " left the thread interrupted");
            } finally {
                qc.close(Wire.CODE_NONE, "done");
            }
        }
    }

    /**
     * kwik turns a pending interrupt into a RuntimeException when a stream
     * is opened: the caller's interrupt, which must not drop a healthy
     * connection.
     */
    static void testAnInterruptDoesNotDropTheConnection() throws Exception {
        try (Rig r = new Rig()) {
            r.answer("{\"status\":204,\"proto\":3}");
            Thread.currentThread().interrupt();
            IOException e = expect(IOException.class, () -> r.t.check(r.p));
            boolean flag = Thread.interrupted();
            check(e instanceof java.io.InterruptedIOException, "an interrupt, not a lost connection: " + e);
            check(flag, "the interrupt is kept");
            check(field(r.t, "conn") == r.qc && r.qc.alive(), "the connection is kept");
            r.t.check(r.p); // and it works
        }
    }

    /** A 426 is a final refusal with the hub's message, whatever its proto (§9, §13.4). */
    static void testA426IsFinal() throws Exception {
        try (Rig r = new Rig()) {
            r.answer("{\"status\":426,\"proto\":4,\"error\":\"upgrade this client to speak QUIC protocol 4\"}");
            io.github.wushilin.pfrelay.StatusException e =
                    expect(io.github.wushilin.pfrelay.StatusException.class, () -> r.t.check(r.p));
            check(e.code() == 426 && e.isFinal(), "426, final: " + e);
            check(e.hubMessage().equals("upgrade this client to speak QUIC protocol 4"), "the hub's message: " + e);
            r.answer("{\"status\":204,\"proto\":4}");
            e = expect(io.github.wushilin.pfrelay.StatusException.class, () -> r.t.check(r.p));
            check(e.code() == 426 && e.isFinal(), "an answer in another protocol is final too: " + e);
        }
    }

    /** A serve answered 200 without a registration id breaks the protocol (§13.4). */
    static void testARegistrationWithoutAnIdIsRefused() throws Exception {
        try (Rig r = new Rig()) {
            r.answer("{\"status\":200,\"proto\":3}");
            IOException e = expect(IOException.class, () -> r.t.register(r.p, "127.0.0.1:1"));
            check(String.valueOf(e.getMessage()).contains("protocol"), "a protocol error: " + e);
        }
    }

    /** After a 429 for the connection, the old connection is closed once it holds nothing (§13.8). */
    static void testARetiredConnectionIsClosed() throws Exception {
        try (Rig r = new Rig()) {
            r.answer("{\"status\":429,\"proto\":3,\"scope\":\"connection\",\"retryAfter\":60,"
                    + "\"error\":\"too many refused requests on this connection; open a new one\"}");
            io.github.wushilin.pfrelay.StatusException e =
                    expect(io.github.wushilin.pfrelay.StatusException.class, () -> r.t.check(r.p));
            check(e.code() == 429, "429: " + e);
            check(field(r.t, "conn") == null, "not used again");
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (r.qc.c.isConnected() && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            check(!r.qc.c.isConnected(), "closed once it held nothing");
        }
    }

    /** The threads of the SDK's pool blocked in a kwik stream read. */
    static int blockedReaders() {
        int n = 0;
        for (Map.Entry<Thread, StackTraceElement[]> e : Thread.getAllStackTraces().entrySet()) {
            if (!e.getKey().getName().startsWith("pfrelay-quic-")) {
                continue;
            }
            for (StackTraceElement f : e.getValue()) {
                if (f.getClassName().contains("StreamInputStreamImpl")) {
                    n++;
                    break;
                }
            }
        }
        return n;
    }

    /**
     * Unregistering and then closing the connection at once leaves no
     * thread behind: kwik wakes only one reader of a stream, so a stream
     * never has two (the registration's watch, and a drain).
     */
    static void testUnregisterThenCloseLeavesNoReader() throws Exception {
        try (Server s = new Server(KEY)) {
            QuicTransport.QConn qc = connect(s);
            int before = blockedReaders();
            QuicStream st = qc.c.createStream(true);
            st.getOutputStream().write(Wire.encode("{\"op\":\"serve\"}"));
            st.getOutputStream().flush();
            QuicTransport.Reg reg = new QuicTransport.Reg(qc, st, "5b2d4e8f1a6c9b0d");
            qc.add(reg);
            Bg.go(reg::watch);
            Thread.sleep(200);
            reg.close(); // the hub never answers the FIN
            qc.close(Wire.CODE_NONE, "done");
            Thread.sleep(500);
            int after = blockedReaders();
            check(after <= before, (after - before) + " threads still blocked in a stream read after the close");
        }
    }

    /**
     * A stream the hub opened and both sides finished cleanly gives the hub
     * one stream credit back, not two: the stream stops reading only while
     * its input is open (kwik gives a credit each time the input closes).
     */
    static void testACleanFinishGivesOneStreamCredit() throws Exception {
        try (Server s = new Server(KEY)) {
            QuicTransport.QConn qc = connect(s);
            try {
                java.util.concurrent.LinkedBlockingQueue<QuicStream> opened = new java.util.concurrent.LinkedBlockingQueue<>();
                qc.c.setPeerInitiatedStreamCallback(opened::add);
                Object streams = field(qc.c, "streamManager");
                int before = (Integer) field(streams, "currentBidirectionalStreamIdLimit");
                int n = 3;
                for (int i = 0; i < n; i++) {
                    QuicStream hs = s.peer().createStream(true);
                    hs.getOutputStream().write(new byte[] {1, 2, 3});
                    hs.getOutputStream().close(); // FIN
                    Thread hub = new Thread(() -> {
                        try {
                            hs.getInputStream().readAllBytes(); // to the client's FIN
                        } catch (IOException ignored) {
                            // reset
                        }
                    });
                    hub.setDaemon(true);
                    hub.start();
                    QuicStream cs = opened.poll(5, java.util.concurrent.TimeUnit.SECONDS);
                    check(cs != null, "the hub's stream arrives");
                    QStream q = new QStream(cs);
                    check(q.input().readAllBytes().length == 3, "read to the hub's FIN");
                    q.finish();
                    q.close();
                    hub.join(5000);
                }
                Thread.sleep(QStream.DELIVER_WAIT_MS + 1000);
                int after = (Integer) field(streams, "currentBidirectionalStreamIdLimit");
                check(after - before == 4 * n, n + " finished streams gave the hub " + (after - before) / 4
                        + " stream credits");
            } finally {
                qc.close(Wire.CODE_NONE, "done");
            }
        }
    }

    /** kwik ends a connection on a fatal error without an event: the keepalive notices, and ends its registrations. */
    static void testAConnectionKwikAbortsIsLost() throws Exception {
        try (Server s = new Server(KEY)) {
            QuicTransport.QConn qc = connect(s);
            QuicTransport.Reg reg = new QuicTransport.Reg(qc, qc.c.createStream(true), "5b2d4e8f1a6c9b0d");
            qc.add(reg);
            ((tech.kwik.core.impl.QuicConnectionImpl) qc.c).abortConnection(null);
            qc.ping();
            IOException e = expect(IOException.class, reg::next);
            check(e.getMessage().contains("lost"), "the registration ends: " + e);
            qc.close(Wire.CODE_NONE, "done");
        }
    }

    /** The serving side's answer to an open, read for at most 5 seconds. */
    static Map<String, Object> answerOf(QuicStream hs) throws Exception {
        java.util.concurrent.CompletableFuture<Map<String, Object>> f = new java.util.concurrent.CompletableFuture<>();
        Thread t = new Thread(() -> {
            try {
                f.complete(Wire.read(hs.getInputStream()));
            } catch (IOException e) {
                f.completeExceptionally(e);
            }
        });
        t.setDaemon(true);
        t.start();
        try {
            return f.get(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            throw new AssertionError("no answer to the open within 5s");
        }
    }

    /**
     * Opens beyond the queue are refused 502 with the backlog's reason
     * (§9), and those still queued when the registration ends are refused
     * 410 at once.
     */
    static void testOpensBeyondTheQueueAndAfterTheEnd() throws Exception {
        try (Server s = new Server(KEY)) {
            QuicTransport.QConn qc = connect(s);
            try {
                QuicStream serve = qc.c.createStream(true);
                serve.getOutputStream().write(Wire.encode("{\"op\":\"serve\"}"));
                QuicTransport.Reg reg = new QuicTransport.Reg(qc, serve, "5b2d4e8f1a6c9b0d");
                qc.add(reg);
                List<QuicStream> opens = new ArrayList<>();
                for (int i = 0; i < QuicTransport.BACKLOG + 2; i++) {
                    QuicStream hs = s.peer().createStream(true);
                    Wire.write(hs.getOutputStream(), "{\"open\":\"" + String.format("%016x", i)
                            + "\",\"reg\":\"5b2d4e8f1a6c9b0d\"}");
                    opens.add(hs);
                }
                // The client takes each open on a thread of its own, so any two of them are the ones refused.
                List<QuicStream> refused = new ArrayList<>();
                long deadline = System.nanoTime() + 5_000_000_000L;
                while (System.nanoTime() < deadline) {
                    refused.clear();
                    for (QuicStream hs : opens) {
                        if (hs.getInputStream().available() > 0) {
                            refused.add(hs);
                        }
                    }
                    if (refused.size() >= 2) {
                        break;
                    }
                    Thread.sleep(20);
                }
                check(refused.size() == 2, refused.size() + " opens answered while the queue holds " + QuicTransport.BACKLOG);
                for (QuicStream hs : refused) {
                    Map<String, Object> a = answerOf(hs);
                    check(a != null && Wire.num(a, "status") == 502
                            && Wire.str(a, "error").equals("the serving side is not accepting connections fast enough"),
                            "an open beyond the queue is refused for the backlog: " + a);
                }
                opens.removeAll(refused);
                reg.end(new IOException("the server ended the registration"));
                for (QuicStream hs : opens) {
                    Map<String, Object> a = answerOf(hs);
                    check(a != null && Wire.num(a, "status") == 410, "a queued open is refused at the end: " + a);
                }
            } finally {
                qc.close(Wire.CODE_NONE, "done");
            }
        }
    }

    /** kwik's words for a refused handshake and a version negotiation (§13.3, §13.7). */
    static void testDialErrors() {
        IOException refused = QuicTransport.dialError(new java.net.ConnectException(
                "Handshake error: Server closed connection: transport error 2: "));
        check(refused instanceof io.github.wushilin.pfrelay.StatusException
                && ((io.github.wushilin.pfrelay.StatusException) refused).code() == 429,
                "CONNECTION_REFUSED is taken as a 429: " + refused);
        IOException other = QuicTransport.dialError(new java.net.ConnectException(
                "Handshake error: Server closed connection: transport error 20: "));
        check(!(other instanceof io.github.wushilin.pfrelay.StatusException), "not another code: " + other);
        IOException vn = QuicTransport.dialError(new java.net.ConnectException(
                "Handshake error: tech.kwik.core.impl.VersionNegotiationFailure"));
        check(vn.getMessage().equals("the hub's QUIC listener does not speak QUIC version 1"), "words: " + vn);
    }

    /** A listener that does not speak QUIC version 1 is named as such (§13.3). */
    static void testVersionNegotiation() throws Exception {
        try (Server s = new Server(KEY, QuicConnection.QuicVersion.V2)) {
            IOException e = expect(IOException.class, () -> connect(s));
            IOException said = QuicTransport.dialError(e);
            check(said.getMessage().equals("the hub's QUIC listener does not speak QUIC version 1"),
                    "said: " + said + " (kwik: " + e + ")");
        }
    }
}
