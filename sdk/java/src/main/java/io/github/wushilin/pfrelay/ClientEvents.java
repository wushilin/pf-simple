package io.github.wushilin.pfrelay;

import java.io.IOException;

/**
 * Handlers a {@link Client} calls as things happen. Every method does
 * nothing by default: override the ones you need, and set them with
 * {@link Client.Builder#events(ClientEvents)}.
 *
 * <p>They are called synchronously, on the SDK's thread where the event
 * happened, so a handler must return quickly and must not block. It may
 * call {@link Client#drop}, {@link Client#conns()} and {@link Client#stats()}.
 * An exception a handler throws is logged and otherwise ignored.
 */
public interface ClientEvents {
    /** A listener or a serve forwarder registered with the hub (true), or lost that registration (false). */
    default void onServing(boolean up) {}

    /**
     * A watch found the tunnel reachable (true) or not (false, with why).
     * Called with the first result and then on every change.
     */
    default void onTunnel(boolean up, IOException error) {}

    /** A connection was opened: dialed, brought in by a listener, or carried by a forwarder. */
    default void onOpen(ConnInfo info) {}

    /**
     * A connection ended, exactly once for each {@link #onOpen}, with its
     * final figures. error is null after a clean finish; otherwise why it
     * failed: a {@link RemoteException} when the far end or the hub said
     * why, a {@link DroppedException} when this side dropped it.
     */
    default void onClose(ConnInfo info, IOException error) {}

    /**
     * This side refused a connection the hub offered, telling the far end
     * reason: the backlog was full, or the target could not be reached. A
     * refused connection is never opened.
     */
    default void onRefuse(ConnId id, String reason) {}
}
