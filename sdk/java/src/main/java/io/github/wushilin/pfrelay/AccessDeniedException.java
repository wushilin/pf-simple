package io.github.wushilin.pfrelay;

import java.util.Map;

/**
 * The hub refused a token or a word (403): a wrong serve token, nobody
 * serving the word, or a missing or wrong client token. The hub does not
 * say which.
 */
public class AccessDeniedException extends StatusException {
    private static final long serialVersionUID = 1L;

    public AccessDeniedException(Map<String, String> headers) {
        super(403, "", headers);
    }

    @Override
    public String getMessage() {
        return "access denied";
    }
}
