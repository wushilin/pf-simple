package io.github.wushilin.pfrelay;

/** Which end of the tunnel a connection belongs to. */
public enum Side {
    /** Opened by {@link Client#dial()}. */
    CONNECT,
    /** Brought in by {@link Listener#accept()}. */
    SERVE;

    @Override
    public String toString() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
