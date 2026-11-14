package io.github.wushilin.pfrelay;

import java.io.IOException;

/** How a connection ended that this side dropped, with {@link Conn#fail} or {@link Client#drop}. */
public class DroppedException extends IOException {
    private static final long serialVersionUID = 1L;
    private final String reason;

    public DroppedException(String reason) {
        super("dropped by this side: " + reason);
        this.reason = reason;
    }

    /** The reason this side gave the far end. */
    public String reason() {
        return reason;
    }
}
