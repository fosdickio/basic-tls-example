package io.fosdick.tlsexample.tls;

import org.bouncycastle.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;

/**
 * This is the actual TLS client that is used for making HTTP calls to the TLS server.
 *
 * @author fosdick.io
 * @since 1.0.0
 */
public class TLSClient implements Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSClient.class);

    private final KeyStore trustStore;
    private final int portNumber;


    /**
     * Base TLS client constructor.
     *
     * @param trustStore the list of certificates from servers that can be trusted.
     * @param portNumber the port number that the socket will connect on.
     */
    public TLSClient(KeyStore trustStore, int portNumber) {
        this.trustStore = trustStore;
        this.portNumber = portNumber;
    }

    /**
     * Brings up a client-side TLS connection.
     */
    public void run() {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", this.portNumber);

            handleClientSideOperations(sslSocket);
        } catch (Exception e) {
            LOG.error("Client exception occurred: " + e.getMessage(), e);
        }
    }

    /**
     * Handles socket-level communications on the client (going to a server).
     *
     * @param clientSocket the socket that's been made available by the server for communication.
     * @throws IOException
     */
    private void handleClientSideOperations(Socket clientSocket) throws IOException {
        OutputStream outputStream = clientSocket.getOutputStream();
        InputStream inputStream = clientSocket.getInputStream();

        outputStream.write(Strings.toByteArray("Hello server"));
        outputStream.write('!');
        outputStream.flush();

        int ch = 0;
        while ((ch = inputStream.read()) != '!') {
            System.out.print((char) ch);
        }
        System.out.println((char) ch);
    }

}
