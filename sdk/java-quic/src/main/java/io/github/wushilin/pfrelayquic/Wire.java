package io.github.wushilin.pfrelayquic;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Protocol 3's values and its message envelope (docs/PROTOCOL.md §13.4,
 * §13.7): a 2-byte big-endian length, then that many bytes of UTF-8 JSON,
 * an object, at most 4096 bytes long.
 */
final class Wire {
    /** The protocol spoken over QUIC. */
    static final int PROTO = 3;
    /** The one ALPN protocol of the hub's QUIC listener (§13.3). */
    static final String ALPN = "pf-tunnel";

    // Application error codes on RESET_STREAM, STOP_SENDING and CONNECTION_CLOSE (§13.7).
    static final long CODE_NONE = 0x0;
    static final long CODE_BROKEN = 0x1;
    static final long CODE_REFUSED = 0x2;
    static final long CODE_PROTOCOL = 0x3;
    static final long CODE_REQUEST_TIMEOUT = 0x4;
    static final long CODE_CANCELLED = 0x5;
    static final long CODE_GOING_AWAY = 0x6;
    static final long CODE_LIMIT = 0x7;

    // How the hub ends a registration, in its "end" message (§13.4).
    static final String END_TAKEOVER = "takeover";

    static final int MAX_MESSAGE = 4096;

    private Wire() {}

    /** A message that breaks the protocol: too long, cut short, or not a JSON object. */
    static final class MessageException extends IOException {
        private static final long serialVersionUID = 1L;

        MessageException(String what) {
            super("a malformed message: " + what);
        }
    }

    /** Encodes one message: the length, then the JSON. */
    static byte[] encode(String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        if (body.length > MAX_MESSAGE) {
            throw new MessageException("longer than " + MAX_MESSAGE + " bytes");
        }
        byte[] out = new byte[2 + body.length];
        out[0] = (byte) (body.length >>> 8);
        out[1] = (byte) body.length;
        System.arraycopy(body, 0, out, 2, body.length);
        return out;
    }

    /** Writes one message. */
    static void write(OutputStream out, String json) throws IOException {
        out.write(encode(json));
        out.flush();
    }

    /**
     * Reads one message, exactly its bytes and nothing after, so the
     * frames that follow are left on the stream. Returns null at a FIN
     * before the message began.
     */
    static Map<String, Object> read(InputStream in) throws IOException {
        byte[] n = new byte[2];
        int got = readFully(in, n);
        if (got == 0) {
            return null;
        }
        if (got < 2) {
            throw new MessageException("the stream ended inside a message");
        }
        int size = ((n[0] & 0xFF) << 8) | (n[1] & 0xFF);
        if (size > MAX_MESSAGE) {
            throw new MessageException("longer than " + MAX_MESSAGE + " bytes");
        }
        byte[] body = new byte[size];
        if (readFully(in, body) < size) {
            throw new MessageException("the stream ended inside a message");
        }
        String text = new String(body, StandardCharsets.UTF_8);
        if (!text.strip().startsWith("{")) {
            throw new MessageException("not a JSON object");
        }
        try {
            return Json.parseObject(text);
        } catch (IOException e) {
            throw new MessageException("not a JSON object");
        }
    }

    private static int readFully(InputStream in, byte[] b) throws IOException {
        int got = 0;
        while (got < b.length) {
            int r = in.read(b, got, b.length - got);
            if (r < 0) {
                break;
            }
            got += r;
        }
        return got;
    }

    /** A string field, or "" when it is missing or not a string. */
    static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof String ? (String) v : "";
    }

    /** A number field, or 0 when it is missing or not a number. */
    static int num(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Number ? ((Number) v).intValue() : 0;
    }

    /** Builds a JSON object of string and number fields, leaving out empty strings. */
    static final class Obj {
        private final StringBuilder b = new StringBuilder("{");

        Obj put(String k, String v) {
            if (v == null || v.isEmpty()) {
                return this;
            }
            sep().append(Json.quote(k)).append(':').append(Json.quote(v));
            return this;
        }

        Obj put(String k, int v) {
            sep().append(Json.quote(k)).append(':').append(v);
            return this;
        }

        private StringBuilder sep() {
            if (b.length() > 1) {
                b.append(',');
            }
            return b;
        }

        @Override
        public String toString() {
            return b + "}";
        }
    }

    /** Keeps printable ASCII, cut to max: how a reason travels to the hub (§6.6). */
    static String ascii(String s, int max) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length() && b.length() < max; i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7F) {
                b.append(c);
            }
        }
        return b.toString();
    }
}
