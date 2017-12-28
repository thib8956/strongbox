package server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsServer;
import core.KeyStoreManager;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class StrongboxHttpsServer {

    private static final String MAIN_CONTEXT = "/";
    private static final String CERT_KEYSTORE_PATH = "src/main/resources/cert.jks";
    private static final String SUN_X_509 = "SunX509";
    private static final String KEYSTORE_PWD = "password";
    private static final String PKSERVER = "/pkserver";
    private static final String ENCODING = "UTF-8";

    private final static Logger logger = Logger.getLogger(StrongboxHttpsServer.class.getName());
    public static final String ADD = "/add";
    private HttpsServer httpsServer;

    public StrongboxHttpsServer() {
        InetSocketAddress address = new InetSocketAddress(8000);
        try {
            httpsServer = HttpsServer.create(address, 0);

            SSLContext sslContext = initSSLContext();
            httpsServer.setHttpsConfigurator(new StrongboxHttpsConfigurator(sslContext));
            httpsServer.createContext(PKSERVER, new StrongBoxHttpHandler(PKSERVER));
            httpsServer.createContext(ADD, new StrongBoxHttpHandler(ADD));
            httpsServer.createContext(MAIN_CONTEXT, new StaticFileHandler("../client"));

            httpsServer.setExecutor(null);
        } catch (GeneralSecurityException | IOException e) {
            logger.log(Level.SEVERE, null, e);
        }
    }

    private SSLContext initSSLContext() throws GeneralSecurityException, IOException {
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        final KeyStoreManager manager = new KeyStoreManager(CERT_KEYSTORE_PATH, KEYSTORE_PWD);
        KeyStore keystore = manager.getKeyStore();
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(SUN_X_509);
        kmf.init(keystore, KEYSTORE_PWD.toCharArray());

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SUN_X_509);
        trustManagerFactory.init(keystore);

        sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    public void start() {
        httpsServer.start();
    }

    public void stop(int retcode) {
        httpsServer.stop(retcode);
    }

    private class StrongBoxHttpHandler implements HttpHandler {

        static final String KEYSTORE_PATH = "src/main/resources/keystore.jks";
        Map<String, String> parameters;
        private String context;


        StrongBoxHttpHandler(String context) {
            super();
            this.context = context;
            parameters = new HashMap<>();
        }

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(httpExchange.getRequestBody(), ENCODING));
            String query = reader.readLine();
            parseQuery(query);

            if (context.equals(PKSERVER)) {
                handlePkserver(httpExchange);
            } else if (context.equals(ADD)) {
                handleAdd(httpExchange);
            }
        }

        private void handlePkserver(HttpExchange httpExchange) throws IOException {
            StringBuilder response = new StringBuilder();

            String providedB64Key = stripHeaders(parameters.get("publickey")).replaceAll("\\s", "");
            String password = parameters.get("password");
            try {
                KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
                final PublicKey publicKey = KeyStoreManager.getPublicKey(providedB64Key);

                final PrivateKey privateKey = manager.getPrivateKey(publicKey, "");
                if (privateKey == null) {
                    throw new InvalidKeyException();
                }

                response.append("Algorithm : ").append(privateKey.getAlgorithm()).append("\n");
                response.append("Format : ").append(privateKey.getFormat()).append("\n");
                response.append(KeyStoreManager.privateKeyToString(privateKey));
            } catch (InvalidKeyException e) {
                logger.log(Level.WARNING, "Invalid public key", e);
                response.append("The provided public key is invalid or wasn't found in the keystore.");
            } catch (GeneralSecurityException e) {
                logger.log(Level.SEVERE, null, e);
            }

            httpExchange.sendResponseHeaders(200, response.length());
            try (OutputStream os = httpExchange.getResponseBody()) {
                os.write(response.toString().getBytes());
            }
        }

        private void handleAdd(HttpExchange httpExchange) throws IOException {
            String providedB64Cert = stripHeaders(parameters.get("cert")).replaceAll("\\s", "");
            String providedB64Key = stripHeaders(parameters.get("privatekey")).replaceAll("\\s", "");
        }

        private void parseQuery(String query) throws UnsupportedEncodingException {
            if (query == null) {
                return;
            }

            final String[] pairs = query.split("[&]");
            for (String pair : pairs) {
                final String[] param = pair.split("[=]");
                String decodedValue =  URLDecoder.decode(param[1], ENCODING);

                parameters.put(param[0], decodedValue);
            }
        }

        private String stripHeaders(String pem) {
            return pem.replaceAll("-----(BEGIN|END) ((PUBLIC|PRIVATE) KEY|CERTIFICATE)-----", "");
        }
    }

    public static void main(String[] args) {
        StrongboxHttpsServer server = new StrongboxHttpsServer();
        server.start();
    }

}
