package io.fosdick.basictlsexample.struct;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Carrier class for a private key and it's corresponding public key certificate.
 *
 * @author fosdick.io
 * @since 1.0.0
 */
public class X509CertPrivateKeyHolder {

    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    /**
     * Base constructor.
     *
     * @param certificate the public key certificate matching privateKey.
     * @param privateKey the private key matching the certificate parameter.
     */
    public X509CertPrivateKeyHolder(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

}
