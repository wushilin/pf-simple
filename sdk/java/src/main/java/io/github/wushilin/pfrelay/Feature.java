package io.github.wushilin.pfrelay;

/** Something a request may depend on that not every protocol has (docs/PROTOCOL.md §5.1). */
public enum Feature {
    /** A client token: registered by serve, sent by connect and check. */
    CLIENT_TOKEN(1, "a client token"),
    /** Serving without a serve token. */
    ANONYMOUS_SERVE(1, "serving without a serve token"),
    /**
     * Reusing the serving side's accept legs (docs/PROTOCOL.md §12).
     * Nothing ever depends on it, so no request names it; listed for the
     * record.
     */
    REUSE(2, "reusing accept legs");

    private final int proto;
    private final String description;

    Feature(int proto, String description) {
        this.proto = proto;
        this.description = description;
    }

    /** The first protocol that has this feature. */
    public int proto() {
        return proto;
    }

    /** What the feature is, for messages. */
    public String description() {
        return description;
    }
}
