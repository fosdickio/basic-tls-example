package io.fosdick.tlsexample.keystore;

import io.fosdick.tlsexample.struct.X509CertPrivateKeyHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * Creates a KeyStore containing a single key with a self-signed certificate.
 *
 * @author fosdick.io
 * @since 1.0.0
 */
public class IdentityStore {

    private final KeyStore identityStore;
    private final char[] identityStorePassword;

    /**
     * Base constructor.
     *
     * @param storePassword the password to unlock the private keys in identityStore.
     */
    public IdentityStore(char[] storePassword) throws Exception {
        this.identityStorePassword = storePassword;
        this.identityStore = createIdentityKeyStore();
    }

    public KeyStore getIdentityStore() {
        return this.identityStore;
    }

    public char[] getIdentityStorePassword() {
        return this.identityStorePassword;
    }

    /**
     * Creates a KeyStore containing a single key with a self-signed certificate.
     *
     * @return a KeyStore containing a single key with a self-signed certificate.
     */
    private KeyStore createIdentityKeyStore() throws Exception {
        X509CertPrivateKeyHolder credentials = createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);
        store.setKeyEntry("identity", credentials.getPrivateKey(), this.identityStorePassword, new Certificate[] {
                credentials.getCertificate()
        });

        return store;
    }

    /**
     * Creates a private key with an associated self-signed certificate (all wrapped in an X500PrivateCredential).
     *
     * @return an X500PrivateCredential containing the key and it's certificate.
     */
    private X509CertPrivateKeyHolder createSelfSignedCredentials() throws GeneralSecurityException, OperatorCreationException {
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");
        KeyPair selfSignedKeyPair = generateECKeyPair("P-256");
        X509CertificateHolder selfSignedCertHolder = createTrustAnchor(selfSignedKeyPair, "SHA256withECDSA");
        X509Certificate selfSignedCert = certConverter.getCertificate(selfSignedCertHolder);

        return new X509CertPrivateKeyHolder(selfSignedCert, selfSignedKeyPair.getPrivate());
    }

    /**
     * Generate an elliptic curve key pair using the specified curve.
     *
     * @return an elliptic curve KeyPair
     */
    private KeyPair generateECKeyPair(String curveName) throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BC");
        keyPair.initialize(new ECGenParameterSpec(curveName));

        return keyPair.generateKeyPair();
    }

    /**
     * Builds a sample self-signed V1 certificate to use as a trust anchor or root certificate.
     *
     * @param keyPair the key pair to use for signing and providing the public key.
     * @param signatureAlgorithm the signature algorithm to sign the certificate with.
     * @return a X509CertificateHolder containing the V1 certificate.
     */
    private X509CertificateHolder createTrustAnchor(KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "USA")
                .addRDN(BCStyle.ST, "California")
                .addRDN(BCStyle.L, "San Francisco")
                .addRDN(BCStyle.O, "fosdick.io")
                .addRDN(BCStyle.CN, "fosdick.io Root Certificate");

        X500Name name = x500NameBuilder.build();

        Date thirtyDaysInFuture = new Date(((System.currentTimeMillis() / 1000) + (24 * 30 * 60 * 60)) * 1000);
        X509v1CertificateBuilder certificateBuilder = new JcaX509v1CertificateBuilder(
                name,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis()),
                thirtyDaysInFuture,
                name,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider("BC")
                .build(keyPair.getPrivate());

        return certificateBuilder.build(signer);
    }

}
