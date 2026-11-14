package io.github.wushilin.pfrelay;

import java.util.Map;

/**
 * The tunnel protocol versions this SDK speaks (docs/PROTOCOL.md §5).
 * Behavior follows the negotiated protocol number only, never a program
 * version.
 */
public final class Proto {
    /** The lowest protocol this SDK speaks: 0, a hub that announces none. */
    public static final int MIN = 0;
    /** The highest protocol this SDK speaks. */
    public static final int MAX = 1;

    /** The header both sides use for the protocol: a range from the client, a number from the hub. */
    public static final String HEADER = "X-PF-Tunnel-Proto";

    private static final Map<Integer, String> RELEASE = Map.of(0, "0.11.0", 1, "0.14.0");

    private Proto() {}

    /** Formats a range for {@link #HEADER}, as {@code min-max}. */
    public static String range(int min, int max) {
        return min + "-" + max;
    }

    /** The first pf-simple release that speaks protocol {@code proto}. */
    static String releaseOf(int proto) {
        String r = RELEASE.get(proto);
        return r != null ? r : "of a newer release";
    }

    /**
     * Reads the protocol the hub chose from its answer. A missing header, or
     * one that is not a number, is protocol 0.
     */
    static int serverProto(Map<String, String> headers) {
        String v = headers == null ? null : headers.get(HEADER);
        if (v == null) {
            return 0;
        }
        try {
            int n = Integer.parseInt(v.trim());
            return n >= 0 ? n : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
