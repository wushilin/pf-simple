package io.github.wushilin.pfrelay;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** TLS helpers. */
public final class Tls {
    private Tls() {}

    /**
     * An SSLContext that trusts exactly the certificates in a PEM file: the
     * hub's own self-signed certificate, or the CA that issued it. The hub is
     * still verified, its host name included.
     */
    public static SSLContext trusting(Path pemFile) throws IOException {
        try (InputStream in = Files.newInputStream(pemFile)) {
            Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (certs.isEmpty()) {
                throw new IOException("no certificate in " + pemFile);
            }
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int n = 0;
            for (Certificate c : certs) {
                ks.setCertificateEntry("ca" + n++, c);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot use the certificates in " + pemFile + ": " + e.getMessage(), e);
        }
    }
}
