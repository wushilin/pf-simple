package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

/** The hub (or a proxy in front of it) answered with a status that is not success. */
public class StatusException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int code;
    private final String hubMessage;
    private final transient Map<String, String> headers;

    public StatusException(int code, String message) {
        this(code, message, Map.of());
    }

    public StatusException(int code, String message, Map<String, String> headers) {
        super(format(code, message));
        this.code = code;
        this.hubMessage = message == null ? "" : message;
        this.headers = headers == null ? Map.of() : Collections.unmodifiableMap(headers);
    }

    private static String format(int code, String message) {
        if (message == null || message.isEmpty()) {
            return "the server answered " + code;
        }
        return message + " (" + code + ")";
    }

    /** The HTTP status code. */
    public int code() {
        return code;
    }

    /** The hub's own message (the {@code error} field of its JSON), or empty. */
    public String hubMessage() {
        return hubMessage;
    }

    /** The answer's headers; names are case-insensitive. */
    public Map<String, String> headers() {
        return headers;
    }

    /** Whether trying again cannot help: a 4xx other than 408 and 429 (docs/PROTOCOL.md §9). */
    public boolean isFinal() {
        return code >= 400 && code < 500 && code != 408 && code != 429;
    }
}
