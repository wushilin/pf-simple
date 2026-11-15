package io.github.wushilin.pfrelayquic;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.net.ssl.X509TrustManager;

/**
 * Pins the hub's QUIC certificate (docs/PROTOCOL.md §13.3): it is accepted
 * if and only if the SHA-256 of its leaf's DER encoding is one of the
 * fingerprints that discovery announced. Only the chain, the name and the
 * dates go unchecked.
 *
 * <p>The TLS library still verifies the handshake: kwik's TLS engine
 * (agent15) checks the CertificateVerify signature with the leaf's key
 * before it asks this trust manager, so the pin proves that the peer holds
 * the pinned certificate's key.
 */
final class Pin implements X509TrustManager {
    static final String MISMATCH = "the hub's QUIC certificate does not match what its HTTPS endpoint announced";

    private final Set<String> want = new HashSet<>();
    private volatile boolean mismatched;

    Pin(List<String> fingerprints) {
        for (String f : fingerprints) {
            want.add(f.toLowerCase(Locale.ROOT));
        }
    }

    /** The lowercase hex SHA-256 of der. */
    static String fingerprint(byte[] der) {
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(der);
            StringBuilder b = new StringBuilder(64);
            for (byte x : sum) {
                b.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
            }
            return b.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Whether a handshake failed on the pin. */
    boolean mismatched() {
        return mismatched;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            mismatched = true;
            throw new CertificateException(MISMATCH);
        }
        String got;
        try {
            got = fingerprint(chain[0].getEncoded());
        } catch (CertificateEncodingException e) {
            mismatched = true;
            throw new CertificateException(MISMATCH, e);
        }
        if (!want.contains(got)) {
            mismatched = true;
            throw new CertificateException(MISMATCH);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("a client does not check clients");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
