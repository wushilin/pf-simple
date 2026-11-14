package io.github.wushilin.pfrelay;

/**
 * How long the SDK waits for things (docs/PROTOCOL.md §7, §8.5, §9).
 * Package-private, so that tests can make a Client with shorter ones.
 */
record Timing(
        long retryMinMs, // a failed registration is retried after this, doubling ...
        long retryMaxMs, // ... up to this
        long settledMs, // a control channel that lasted this long starts the pauses again
        long recheckMs, // a watched tunnel that is up is checked again this often
        long controlPingMs,
        int controlSilenceMs,
        long pingEveryMs, // on streams
        int linkSilenceMs,
        long verdictMs) { // after a clean finish on an offered leg, the wait for the hub's verdict (§12.5)

    static final Timing DEFAULT = new Timing(1000, 30_000, 60_000, 30_000, 20_000, 60_000, 10_000, 30_000, 3000);

    /** The pause after the one that was just waited. */
    long next(long backoff) {
        return Math.min(backoff * 2, retryMaxMs);
    }
}
