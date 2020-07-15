package io.fosdick.tlsexample;

import java.security.Security;

import io.fosdick.tlsexample.keystore.IdentityStore;
import io.fosdick.tlsexample.tls.TLSClient;
import io.fosdick.tlsexample.tls.TLSServer;
import io.fosdick.tlsexample.keystore.TrustStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * This is the main application class that provides a basic example of communications between a HTTP client and server
 * using sockets.  These communications run over TLS and make use of the Bouncy Castle APIs.
 *
 * @author fosdick.io
 * @since 1.0.0
 */
public class MainApplication {

    private static final char[] IDENTITY_STORE_PASSWORD = "ThisIsOnlyTemporaryAndWillBeChanged".toCharArray();
    private static final int PORT_NUMBER = 8080;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        // Server
        IdentityStore serverStore = new IdentityStore(IDENTITY_STORE_PASSWORD);
        TLSServer server = new TLSServer(serverStore, PORT_NUMBER);
        server.start();

        // Client
        TrustStore trustStore = new TrustStore(serverStore.getIdentityStore());
        new Thread(new TLSClient(trustStore.getTrustStore(), PORT_NUMBER)).start();
    }

}
