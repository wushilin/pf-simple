package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Just enough JSON for the hub's few objects: parse any value into Maps,
 * Lists, Strings, Doubles, Booleans and null; quote a string.
 */
final class Json {
    private final String s;
    private int i;
    private int depth;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) throws IOException {
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) {
            throw p.error("trailing characters");
        }
        return v;
    }

    /** Parses an object; anything else is an error. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) throws IOException {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new IOException("not a JSON object");
        }
        return (Map<String, Object>) v;
    }

    private IOException error(String what) {
        return new IOException("invalid JSON at " + i + ": " + what);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            i++;
        }
    }

    private Object value() throws IOException {
        if (i >= s.length()) {
            throw error("unexpected end");
        }
        char c = s.charAt(i);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                return literal("true", Boolean.TRUE);
            case 'f':
                return literal("false", Boolean.FALSE);
            case 'n':
                return literal("null", null);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return number();
                }
                throw error("unexpected character");
        }
    }

    private Object literal(String word, Object v) throws IOException {
        if (!s.startsWith(word, i)) {
            throw error("unexpected literal");
        }
        i += word.length();
        return v;
    }

    private Map<String, Object> object() throws IOException {
        if (++depth > 64) {
            throw error("too deep");
        }
        i++; // {
        Map<String, Object> m = new LinkedHashMap<>();
        ws();
        if (i < s.length() && s.charAt(i) == '}') {
            i++;
            depth--;
            return m;
        }
        while (true) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') {
                throw error("expected a key");
            }
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') {
                throw error("expected ':'");
            }
            i++;
            ws();
            m.put(k, value());
            ws();
            if (i >= s.length()) {
                throw error("unexpected end");
            }
            char c = s.charAt(i++);
            if (c == '}') {
                depth--;
                return m;
            }
            if (c != ',') {
                throw error("expected ',' or '}'");
            }
        }
    }

    private List<Object> array() throws IOException {
        if (++depth > 64) {
            throw error("too deep");
        }
        i++; // [
        List<Object> l = new ArrayList<>();
        ws();
        if (i < s.length() && s.charAt(i) == ']') {
            i++;
            depth--;
            return l;
        }
        while (true) {
            ws();
            l.add(value());
            ws();
            if (i >= s.length()) {
                throw error("unexpected end");
            }
            char c = s.charAt(i++);
            if (c == ']') {
                depth--;
                return l;
            }
            if (c != ',') {
                throw error("expected ',' or ']'");
            }
        }
    }

    private String string() throws IOException {
        i++; // "
        StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) {
                throw error("unterminated string");
            }
            char c = s.charAt(i++);
            if (c == '"') {
                return b.toString();
            }
            if (c < 0x20) {
                throw error("control character in string");
            }
            if (c != '\\') {
                b.append(c);
                continue;
            }
            if (i >= s.length()) {
                throw error("unterminated escape");
            }
            char e = s.charAt(i++);
            switch (e) {
                case '"': b.append('"'); break;
                case '\\': b.append('\\'); break;
                case '/': b.append('/'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length()) {
                        throw error("short \\u escape");
                    }
                    try {
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    } catch (NumberFormatException x) {
                        throw error("bad \\u escape");
                    }
                    i += 4;
                    break;
                default:
                    throw error("bad escape");
            }
        }
    }

    private Double number() throws IOException {
        int start = i;
        if (s.charAt(i) == '-') {
            i++;
        }
        while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) {
            i++;
        }
        try {
            return Double.valueOf(s.substring(start, i));
        } catch (NumberFormatException e) {
            throw error("bad number");
        }
    }

    /** A JSON string literal for s. */
    static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }
}
