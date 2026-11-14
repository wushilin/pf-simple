package io.github.wushilin.pfrelay;

import java.util.Locale;

/** The hub's tunnel endpoints (docs/PROTOCOL.md §6). */
enum Endpoint {
    SERVE, CONNECT, ACCEPT, CHECK, VERSION;

    /** The request path, under /pf/api/tunnel/. */
    String path() {
        return Client.PATH + name().toLowerCase(Locale.ROOT);
    }
}
