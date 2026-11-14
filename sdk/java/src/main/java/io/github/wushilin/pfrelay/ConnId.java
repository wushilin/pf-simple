package io.github.wushilin.pfrelay;

import java.util.Objects;

/**
 * Names one connection through the tunnel: the id the hub gave it, the same
 * on both ends of the tunnel. It is opaque: compare it, use it as a map key,
 * print it with {@link #toString()}.
 */
public final class ConnId {
    private final String id;

    ConnId(String id) {
        this.id = Objects.requireNonNull(id);
    }

    /** The start of the id, enough to tell connections apart in a log. */
    public String shortForm() {
        return id.length() > 8 ? id.substring(0, 8) : id;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ConnId && ((ConnId) o).id.equals(id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    /** The id as the hub gave it: 16 hex digits. */
    @Override
    public String toString() {
        return id;
    }
}
