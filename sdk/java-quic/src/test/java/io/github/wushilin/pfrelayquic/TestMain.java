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
            if (m.getName().startsWith("test") && Modifier.isStatic(m.getModifiers())) {
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

        Server(String key) throws Exception {
            String b64 = key.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            java.security.PrivateKey pk = java.security.KeyFactory.getInstance("EC")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(b64)));
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            char[] pw = "test".toCharArray();
            ks.setKeyEntry("hub", pk, pw, new java.security.cert.Certificate[] {cert()});
            DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            port = socket.getLocalPort();
            connector = ServerConnector.builder()
                    .withSocket(socket)
                    .withKeyStore(ks, "hub", pw, "secp256r1")
                    .withLogger(new tech.kwik.core.log.NullLogger())
                    .withSupportedVersion(QuicConnection.QuicVersion.V1)
                    .withConfiguration(ServerConnectionConfig.builder()
                            .maxIdleTimeoutInSeconds(30)
                            .maxOpenPeerInitiatedBidirectionalStreams(10)
                            .maxOpenPeerInitiatedUnidirectionalStreams(0)
                            .build())
                    .build();
            connector.registerApplicationProtocol(Wire.ALPN, new ApplicationProtocolConnectionFactory() {
                @Override
                public ApplicationProtocolConnection createConnection(String protocol, QuicConnection c) {
                    return new ApplicationProtocolConnection() {};
                }
            });
            connector.start();
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
}
