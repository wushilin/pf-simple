package io.github.wushilin.pfrelay;

import java.io.IOException;

/**
 * The far end or the hub dropped the connection, with this reason (an
 * {@code err:} frame, docs/PROTOCOL.md §8.3). The reason is untrusted text:
 * it has been stripped of unprintable characters and cut to 200.
 */
public class RemoteException extends IOException {
    private static final long serialVersionUID = 1L;
    private final String reason;

    public RemoteException(String reason) {
        super(reason);
        this.reason = reason;
    }

    /** The reason the far end gave. */
    public String reason() {
        return reason;
    }
}
