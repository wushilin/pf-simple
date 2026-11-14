package io.github.wushilin.pfrelay;

/**
 * The hub's answer to a version probe (docs/PROTOCOL.md §6.5).
 *
 * @param version  the hub's program version, such as {@code 0.14.0}
 * @param protoMin the lowest tunnel protocol it speaks
 * @param protoMax the highest tunnel protocol it speaks
 * @param token    the name of the serve token that asked
 */
public record ServerInfo(String version, int protoMin, int protoMax, String token) {
    /** This answer as one line of JSON. */
    public String toJson() {
        return "{\"version\":" + Json.quote(version) + ",\"protoMin\":" + protoMin
                + ",\"protoMax\":" + protoMax + ",\"token\":" + Json.quote(token) + "}";
    }
}
