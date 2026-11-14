package io.github.wushilin.pfrelay;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * The few HTTP/1.1 requests the protocol needs, over TLS: a GET, or a GET
 * that upgrades to a WebSocket. Written by hand because the JDK's
 * WebSocket hides the handshake's answer.
 */
final class Http {
    static final int DIAL_TIMEOUT_MS = 10_000;
    static final int HANDSHAKE_TIMEOUT_MS = 15_000;
    static final int MAX_BODY = 64 << 10;
    private static final String WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Http() {}

    /** A hub's address. */
    static final class Target {
        final String host; // without brackets, for the socket and TLS
        final int port;
        final String hostHeader; // as the Host header gives it

        Target(String host, int port, String hostHeader) {
            this.host = host;
            this.port = port;
            this.hostHeader = hostHeader;
        }
    }

    /** An answer: its status, headers and (unless it upgraded) its body. */
    static final class Response {
        int status;
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        byte[] body = new byte[0];
        WebSocket ws; // on a 101

        String errorText() {
            return Http.errorText(body);
        }
    }

    /**
     * Sends GET path with headers. With upgrade, asks for a WebSocket: a 101
     * comes back with {@code ws} set; anything else with its body read and
     * the connection closed.
     */
    static Response request(Target t, String path, Map<String, String> headers, SSLContext ctx, boolean upgrade)
            throws IOException {
        Socket raw = new Socket();
        SSLSocket ssl = null;
        boolean keep = false;
        try {
            raw.setTcpNoDelay(true);
            raw.connect(new InetSocketAddress(t.host, t.port), DIAL_TIMEOUT_MS);
            raw.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            ssl = (SSLSocket) ctx.getSocketFactory().createSocket(raw, t.host, t.port, true);
            SSLParameters params = ssl.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            params.setApplicationProtocols(new String[] {"http/1.1"});
            ssl.setSSLParameters(params);
            ssl.setUseClientMode(true);
            ssl.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            ssl.startHandshake();

            String key = null;
            StringBuilder req = new StringBuilder(512);
            req.append("GET ").append(path).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(t.hostHeader).append("\r\n");
            req.append("User-Agent: pfrelay-java\r\n");
            if (upgrade) {
                byte[] nonce = new byte[16];
                RANDOM.nextBytes(nonce);
                key = Base64.getEncoder().encodeToString(nonce);
                req.append("Upgrade: websocket\r\nConnection: Upgrade\r\n");
                req.append("Sec-WebSocket-Key: ").append(key).append("\r\n");
                req.append("Sec-WebSocket-Version: 13\r\n");
            } else {
                req.append("Connection: close\r\n");
            }
            for (Map.Entry<String, String> h : headers.entrySet()) {
                req.append(h.getKey()).append(": ").append(headerValue(h.getValue())).append("\r\n");
            }
            req.append("\r\n");
            OutputStream out = ssl.getOutputStream();
            out.write(req.toString().getBytes(StandardCharsets.UTF_8));
            out.flush();

            InputStream in = new BufferedInputStream(ssl.getInputStream(), 16 << 10);
            Response resp = readHead(in);
            if (upgrade && resp.status == 101) {
                if (!accept(key).equals(resp.headers.get("Sec-WebSocket-Accept"))) {
                    throw new IOException("the server's websocket handshake is invalid");
                }
                ssl.setSoTimeout(0);
                resp.ws = new WebSocket(ssl, raw, in, out, true, resp.headers);
                keep = true;
                return resp;
            }
            resp.body = readBody(in, resp);
            return resp;
        } finally {
            if (!keep) {
                try {
                    raw.close();
                } catch (IOException ignored) {
                    // done with it
                }
            }
        }
    }

    /** Header values may not break the request: drop CR, LF and other controls. */
    static String headerValue(String v) {
        StringBuilder b = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c >= 0x20 && c != 0x7F) {
                b.append(c);
            }
        }
        return b.toString();
    }

    static String accept(String key) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] sum = sha1.digest((key + WS_GUID).getBytes(StandardCharsets.US_ASCII));
            return Base64.getEncoder().encodeToString(sum);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(128);
        while (true) {
            int c = in.read();
            if (c < 0) {
                throw new EOFException("the server closed the connection during the handshake");
            }
            if (c == '\n') {
                break;
            }
            if (b.size() > 16 << 10) {
                throw new IOException("the server's answer has a line that is too long");
            }
            b.write(c);
        }
        String s = b.toString(StandardCharsets.ISO_8859_1);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    static Response readHead(InputStream in) throws IOException {
        Response r = new Response();
        String status = readLine(in);
        String[] parts = status.split(" ", 3);
        if (parts.length < 2 || !parts[0].startsWith("HTTP/1.")) {
            throw new IOException("the server did not answer with HTTP/1.1");
        }
        try {
            r.status = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IOException("the server's answer has no status code");
        }
        for (int n = 0;; n++) {
            String line = readLine(in);
            if (line.isEmpty()) {
                break;
            }
            if (n > 200) {
                throw new IOException("the server's answer has too many headers");
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            r.headers.putIfAbsent(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
        }
        return r;
    }

    /** Reads at most MAX_BODY of the body; what is past that is not needed. */
    static byte[] readBody(InputStream in, Response r) throws IOException {
        if (r.status < 200 || r.status == 204 || r.status == 304) {
            return new byte[0];
        }
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try {
            String te = r.headers.get("Transfer-Encoding");
            String cl = r.headers.get("Content-Length");
            if (te != null && te.toLowerCase(java.util.Locale.ROOT).contains("chunked")) {
                while (b.size() < MAX_BODY) {
                    String line = readLine(in);
                    int semi = line.indexOf(';');
                    long size = Long.parseLong((semi >= 0 ? line.substring(0, semi) : line).trim(), 16);
                    if (size == 0) {
                        break;
                    }
                    copy(in, b, size);
                    readLine(in); // the CRLF after the chunk
                }
            } else if (cl != null) {
                copy(in, b, Long.parseLong(cl.trim()));
            } else {
                copy(in, b, MAX_BODY);
            }
        } catch (IOException | NumberFormatException e) {
            // what was read is what there is
        }
        return b.toByteArray();
    }

    private static void copy(InputStream in, ByteArrayOutputStream b, long n) throws IOException {
        byte[] buf = new byte[4096];
        while (n > 0 && b.size() < MAX_BODY) {
            int k = in.read(buf, 0, (int) Math.min(buf.length, Math.min(n, MAX_BODY - b.size())));
            if (k < 0) {
                return;
            }
            b.write(buf, 0, k);
            n -= k;
        }
    }

    /**
     * The message in an error answer: the hub sends {"error": "..."}; a
     * proxy in front of it may send anything, of which a short plain text is
     * shown.
     */
    static String errorText(byte[] body) {
        String raw = new String(body, 0, Math.min(body.length, 2048), StandardCharsets.UTF_8);
        try {
            Object e = Json.parseObject(raw).get("error");
            if (e instanceof String && !((String) e).isEmpty()) {
                return (String) e;
            }
        } catch (IOException ignored) {
            // not JSON
        }
        String text = raw.strip();
        if (text.length() < 200 && !text.contains("<")) {
            return text;
        }
        return "";
    }

    static Map<String, String> headers() {
        return new LinkedHashMap<>();
    }
}
