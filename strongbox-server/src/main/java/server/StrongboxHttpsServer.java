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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class StrongboxHttpsServer {

    private static final String MAIN_CONTEXT = "/";
    private static final String KEYSTORE_PATH = "src/main/resources/cert.jks";
    private static final String SUN_X_509 = "SunX509";
    private static final String KEYSTORE_PWD = "password";

    private final Logger logger = Logger.getLogger(StrongboxHttpsServer.class.getName());
    private HttpsServer httpsServer;

    public StrongboxHttpsServer() {
        InetSocketAddress address = new InetSocketAddress(8000);
        try {
            httpsServer = HttpsServer.create(address, 0);

            SSLContext sslContext = initSSLContext();
            httpsServer.setHttpsConfigurator(new StrongboxHttpsConfigurator(sslContext));
            httpsServer.createContext("/pkserver", new StrongBoxHttpHandler());
            httpsServer.createContext(MAIN_CONTEXT, new StaticFileHandler("../client"));
            httpsServer.setExecutor(null);

        } catch (GeneralSecurityException | IOException e) {
            logger.log(Level.SEVERE, null, e);
        }
    }

    private SSLContext initSSLContext() throws GeneralSecurityException, IOException {
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        final KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, KEYSTORE_PWD);
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

        Map<String, String> parameters;

        StrongBoxHttpHandler() {
            super();
            parameters = new HashMap<>();
        }

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(httpExchange.getRequestBody(), "utf-8"));
            String query = reader.readLine();
            parseQuery(query);

            StringBuilder response = new StringBuilder();

            // TODO: Check passwd in POST request to access the keystore.
            try {
                KeyStoreManager manager = new KeyStoreManager("src/main/resources/keystore.jks", "password");
                for (Certificate cert : manager.geyCertificates()) {
                    response.append(cert.getPublicKey().getAlgorithm()).append("\n");
                    response.append(cert.getPublicKey().getFormat()).append("\n");
                    response.append(Base64.getEncoder().encodeToString(cert.getEncoded())).append("\n");
                }
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }

            for (Map.Entry<String, String> param : parameters.entrySet()) {
                response.append(param.getKey()).append(" ").append(param.getValue()).append("\n");
            }

            httpExchange.sendResponseHeaders(200, response.length());
            try (OutputStream os = httpExchange.getResponseBody()) {
                os.write(response.toString().getBytes());
            }
        }

        private void parseQuery(String query) {
            if (query == null) {
                return;
            }
            final String[] pairs = query.split("[&]");
            for (String pair : pairs) {
                final String[] param = pair.split("[=]");
                parameters.put(param[0], param[1]);
            }
        }
    }

    public static void main(String[] args) {
        StrongboxHttpsServer server = new StrongboxHttpsServer();
        server.start();
    }

}
