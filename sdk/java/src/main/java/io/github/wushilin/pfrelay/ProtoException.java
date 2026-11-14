package io.github.wushilin.pfrelay;

import java.io.IOException;

/**
 * The hub is too old for a feature this request depends on
 * (docs/PROTOCOL.md §5.3). Waiting or retrying cannot help.
 */
public class ProtoException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int serverProto;
    private final Feature need;

    public ProtoException(int serverProto, Feature need) {
        super(format(serverProto, need));
        this.serverProto = serverProto;
        this.need = need;
    }

    private static String format(int server, Feature need) {
        String speaks = server == 0 ? "it announces no tunnel protocol" : "it speaks tunnel protocol " + server;
        return "this server is too old for " + need.description() + ": " + speaks + ", and that needs protocol "
                + need.proto() + " (pf-simple " + Proto.releaseOf(need.proto())
                + " or later). Upgrade the server, or do without it";
    }

    /** The protocol the hub speaks. */
    public int serverProto() {
        return serverProto;
    }

    /** What was asked for. */
    public Feature need() {
        return need;
    }
}
