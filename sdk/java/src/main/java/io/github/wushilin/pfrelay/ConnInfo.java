package io.github.wushilin.pfrelay;

import java.time.Instant;

/**
 * A snapshot of one connection.
 *
 * @param id       the hub's connection id
 * @param side     which end of the tunnel this is
 * @param opened   when the connection was opened
 * @param sent     bytes sent into the tunnel
 * @param received bytes received from the tunnel
 * @param wroteEof this end has half-closed
 * @param readEof  the far end has half-closed
 */
public record ConnInfo(ConnId id, Side side, Instant opened, long sent, long received,
                       boolean wroteEof, boolean readEof) {}
