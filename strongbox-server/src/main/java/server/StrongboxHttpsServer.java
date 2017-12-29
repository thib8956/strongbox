package server;

import com.sun.net.httpserver.HttpsServer;
import core.KeyStoreManager;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Private key server secured by HTTPS protocol. Allow finding, adding or removing keys from the server.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 *
 */
public class StrongboxHttpsServer {

    private final static Logger logger = Logger.getLogger(StrongboxHttpsServer.class.getName());

    private static final String ROOT = "../client";
    private static final String CERT_KEYSTORE_PATH = "src/main/resources/cert.jks";
    private static final String SUN_X_509 = "SunX509";
    private static final String KEYSTORE_PWD = "password";
    private static final String PROTOCOL = "TLS";
    static final String ENCODING = "UTF-8";

    private HttpsServer httpsServer;

    /**
     * Constructor for the StrongBoxHttpsServer.
     * Initialize the StrongBox context
     * @see StrongboxHttpsConfigurator
     */
    public StrongboxHttpsServer() {
        try {
            InetSocketAddress address = new InetSocketAddress(8000);
            httpsServer = HttpsServer.create(address, 0);

            SSLContext sslContext = initSSLContext();
            httpsServer.setHttpsConfigurator(new StrongboxHttpsConfigurator(sslContext));
            httpsServer.createContext(Context.PKSERVER.name, new StrongBoxHttpHandler(Context.PKSERVER));
            httpsServer.createContext(Context.ADD.name, new StrongBoxHttpHandler(Context.ADD));
            httpsServer.createContext(Context.DELETE.name, new StrongBoxHttpHandler(Context.DELETE));
            httpsServer.createContext(Context.MAIN.name, new StaticFileHandler(ROOT));
            httpsServer.setExecutor(null);
        } catch (GeneralSecurityException | IOException e) {
            logger.log(Level.SEVERE, null, e);
        }
    }

    /**
     * Initialize a SSLContext.
     * @return The SSLContext initialized.
     * @throws GeneralSecurityException if a security manager exists and its checkRead method denies read access to the file.
     * @throws IOException if the file does not exist, is a directory rather than a regular file, or for some other reason cannot be opened for reading.
     */
    private SSLContext initSSLContext() throws GeneralSecurityException, IOException {
        final SSLContext sslContext = SSLContext.getInstance(PROTOCOL);
        final KeyStoreManager manager = new KeyStoreManager(CERT_KEYSTORE_PATH, KEYSTORE_PWD);
        KeyStore keystore = manager.getKeyStore();
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(SUN_X_509);
        kmf.init(keystore, KEYSTORE_PWD.toCharArray());

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SUN_X_509);
        trustManagerFactory.init(keystore);

        sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    /**
     * Start the server.
     * @see com.sun.net.httpserver.HttpServer#start()
     */
    public void start() {
        httpsServer.start();
    }

    /**
     * Stop the server.
     * @param retcode The maximum time in seconds to wait until exchanges have finished.
     * @see com.sun.net.httpserver.HttpServer#stop(int delay)
     */
    public void stop(int retcode) {
        httpsServer.stop(retcode);
    }

    public static void main(String[] args) {
        StrongboxHttpsServer server = new StrongboxHttpsServer();
        server.start();
    }
}
