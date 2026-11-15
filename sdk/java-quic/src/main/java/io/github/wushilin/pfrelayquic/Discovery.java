package io.github.wushilin.pfrelayquic;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Where the hub's QUIC listener is, and its certificates' fingerprints (docs/PROTOCOL.md §13.2). */
record Discovery(String host, int port, List<String> fingerprints) {
    /** Reads and checks the 200 body of discovery; unknown fields are ignored. */
    static Discovery parse(String body) throws IOException {
        Map<String, Object> m;
        try {
            m = Json.parseObject(body);
        } catch (IOException e) {
            throw new IOException("the hub's answer to QUIC discovery is not understood");
        }
        Object h = m.get("host");
        Object p = m.get("port");
        Object f = m.get("fingerprints");
        if (!(h instanceof String) || !(p instanceof Number) || !(f instanceof List)) {
            throw new IOException("the hub's answer to QUIC discovery is not understood");
        }
        String host = (String) h;
        double port = ((Number) p).doubleValue();
        List<String> fps = new ArrayList<>();
        for (Object o : (List<?>) f) {
            if (!(o instanceof String)) {
                throw new IOException("the hub advertised a bad certificate fingerprint");
            }
            fps.add((String) o);
        }
        if (host.isEmpty() || host.chars().anyMatch(c -> c == '[' || c == ']' || c == '/' || c <= ' ')) {
            throw new IOException("the hub advertised a bad QUIC host \"" + host + "\"");
        }
        if (port != Math.rint(port) || port < 1 || port > 65535) {
            throw new IOException("the hub advertised a bad QUIC port " + p);
        }
        if (fps.isEmpty() || fps.size() > 4) {
            throw new IOException("the hub advertised no usable certificate fingerprints");
        }
        for (String fp : fps) {
            if (fp.length() != 64 || !fp.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
                throw new IOException("the hub advertised a bad certificate fingerprint \"" + fp + "\"");
            }
        }
        return new Discovery(host, (int) port, List.copyOf(fps));
    }

    /** Whether host is an IP address rather than a DNS name. */
    boolean hostIsIp() {
        if (host.indexOf(':') >= 0) {
            return true; // IPv6, given without brackets
        }
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(c -> c >= '0' && c <= '9')
                    || Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }
}
