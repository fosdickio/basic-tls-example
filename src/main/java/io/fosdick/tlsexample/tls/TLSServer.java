package io.fosdick.tlsexample.tls;

import io.fosdick.tlsexample.keystore.IdentityStore;
import org.bouncycastle.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;

/**
 * This is the TLS server that is used for receiving HTTP requests from a client.
 *
 * @author fosdick.io
 * @since 1.0.0
 */
public class TLSServer {

    private static final Logger LOG = LoggerFactory.getLogger(TLSServer.class);

    private final CountDownLatch readyLatch = new CountDownLatch(1);

    private final KeyStore serverStore;
    private final char[] serverStorePassword;
    private final int portNumber;

    /**
     * Base TLS server constructor.
     *
     * @param identityStore contains the public/private keys for the server and the password to unlock the private
     *                         keys in serverStore.
     * @param portNumber the port number that the socket will connect on.
     */
    public TLSServer(IdentityStore identityStore, int portNumber) {
        this.serverStore = identityStore.getIdentityStore();
        this.serverStorePassword = identityStore.getIdentityStorePassword();
        this.portNumber = portNumber;
    }

    /**
     * Brings up a server-side TLS connection.
     */
    public void start() throws InterruptedException {
        LOG.info("Starting server...");
        new Thread(new ServerTask()).start();
        readyLatch.await();
    }

    /**
     * Implements a threaded approach to bringing up the server-side TLS connection.
     */
    private class ServerTask implements Runnable {

        public void run() {
            try {
                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
                keyMgrFact.init(serverStore, serverStorePassword);

                SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");
                sslContext.init(keyMgrFact.getKeyManagers(), null, null);

                SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
                SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(portNumber);

                readyLatch.countDown();

                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

                handleServerSideOperations(sslSocket);
            } catch (Exception e) {
                LOG.error("Server exception occurred: " + e.getMessage(), e);
            }
        }

        /**
         * Handles socket-level communications on the server (coming from a client).
         *
         * @param serverSocket the socket that's been made available by the server for communication.
         * @throws IOException
         */
        private void handleServerSideOperations(Socket serverSocket) throws IOException {
            LOG.info("Starting session...");
            InputStream inputStream = serverSocket.getInputStream();
            OutputStream outputStream = serverSocket.getOutputStream();

            outputStream.write(Strings.toByteArray("Request: "));
            int ch = 0;
            while ((ch = inputStream.read()) != '!') {
                outputStream.write(ch);
            }
            outputStream.write('!');

            serverSocket.close();
            LOG.info("Session closed.");
        }

    }

}
