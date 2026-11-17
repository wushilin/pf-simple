package io.github.wushilin.pfrelay;

import java.util.Locale;

/** The hub's tunnel endpoints (docs/PROTOCOL.md §6). */
enum Endpoint {
    SERVE, CONNECT, ACCEPT, CHECK, VERSION;

    /** The endpoint's last path segment: serve, connect, ... (see {@link Client#apiPath}). */
    String segment() {
        return name().toLowerCase(Locale.ROOT);
    }
}
