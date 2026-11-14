package io.github.wushilin.pfrelay;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.regex.Pattern;

/** Tunnel words (docs/PROTOCOL.md §3.1): three groups of four letters or digits. */
public final class Words {
    private static final String ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
    private static final Pattern PATTERN = Pattern.compile("^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$");
    private static final SecureRandom RANDOM = new SecureRandom();

    private Words() {}

    /** A random word that is easy to read out: no {@code 0 o 1 i l}. */
    public static String newWord() {
        StringBuilder b = new StringBuilder(14);
        for (int i = 0; i < 12; i++) {
            if (i == 4 || i == 8) {
                b.append('-');
            }
            b.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return b.toString();
    }

    /**
     * Trims and lower-cases a word, and checks it.
     *
     * @throws IllegalArgumentException if it is not a word
     */
    public static String normalize(String word) {
        String w = word == null ? "" : word.strip().toLowerCase(Locale.ROOT);
        if (!PATTERN.matcher(w).matches()) {
            throw new IllegalArgumentException("the word must be three groups of four letters or digits, "
                    + "like k3f9-x2mq-7hpa (case does not matter)");
        }
        return w;
    }
}
