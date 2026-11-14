package io.github.wushilin.pfrelay;

/**
 * A client's connection totals since it was made, open connections included.
 *
 * @param opened   connections opened
 * @param active   connections open now
 * @param failed   connections that ended with an error
 * @param sent     bytes sent into the tunnel
 * @param received bytes received from the tunnel
 */
public record Stats(long opened, long active, long failed, long sent, long received) {}
