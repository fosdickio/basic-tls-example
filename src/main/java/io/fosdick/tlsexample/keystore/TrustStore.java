package io.fosdick.tlsexample.keystore;

import java.security.KeyStore;
import java.util.Enumeration;

/**
 * Creates a key store suitable for use as a trust store.  It contains only the certificates associated with each
 * alias in the passed in credentialStore.
 *
 * @author fosdick.io
 * @since 1.0.0
 */
public class TrustStore {

    private final KeyStore trustStore;

    /**
     * Base constructor.
     *
     * @param credentialStore key store containing public/private credentials.
     */
    public TrustStore(KeyStore credentialStore) throws Exception {
        this.trustStore = createTrustStore(credentialStore);
    }

    public KeyStore getTrustStore() {
        return this.trustStore;
    }

    /**
     * Creates a key store suitable for use as a trust store.  It contains only the certificates associated with each
     * alias in the passed in credentialStore.
     *
     * @param credentialStore key store containing public/private credentials.
     * @return a key store containing only certificates.
     */
    private KeyStore createTrustStore(KeyStore credentialStore) throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);

        for (Enumeration<String> enumeration = credentialStore.aliases(); enumeration.hasMoreElements();) {
            String alias = enumeration.nextElement();
            store.setCertificateEntry(alias, credentialStore.getCertificate(alias));
        }

        return store;
    }

}
