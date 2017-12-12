package server;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HttpsHelloServer {

    private static final String CONTEXT = "/test";
    private static final String KEYSTORE_PATH = "res/keystore.jks";
    private static final String SUN_X_509 = "SunX509";

    private HttpsServer httpsServer;
    private final Logger logger = Logger.getLogger(HttpsHelloServer.class.getName());
    private static final char[] KEYSTORE_PWD = "password".toCharArray();

    public HttpsHelloServer() {
        InetSocketAddress address = new InetSocketAddress(8000);
        try {
            httpsServer = HttpsServer.create(address, 0);

            SSLContext sslContext = initSSLContext();
            httpsServer.setHttpsConfigurator(new HttpsHelloServer.HelloHttpsConfigurator(sslContext));
            httpsServer.createContext(CONTEXT, new HelloHandler());
            httpsServer.createContext("/pkserver", new PrivateKeyHandler());
            httpsServer.setExecutor(null);

        } catch (GeneralSecurityException | IOException e) {
            logger.log(Level.SEVERE, null, e);
        }
    }

    private SSLContext initSSLContext() throws GeneralSecurityException, IOException {
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        final KeyStore ks = KeyStore.getInstance("JKS");

        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, KEYSTORE_PWD);
        }

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(SUN_X_509);
        kmf.init(ks, KEYSTORE_PWD);

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SUN_X_509);
        trustManagerFactory.init(ks);
        sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    public void start() {
        httpsServer.start();
    }

    public void stop(int retcode) {
        httpsServer.stop(retcode);
    }
  
    public class HelloHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            String response = "<h1>Hello world !</h1>";
            final String requestedUri = httpExchange.getRequestURI().toString();
            // Log the client request.
            logger.info(httpExchange.getRequestMethod() + " " + requestedUri);
            //BufferedReader reader = new BufferedReader(new InputStreamReader(httpExchange.getRequestBody()));
            //logger.info(new BufferedReader(new InputStreamReader(httpExchange.getRe())).readLine());

            httpExchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            httpExchange.sendResponseHeaders(200, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            logger.info("Connexion done");
            os.close();
        }
    }

    private class PrivateKeyHandler implements HttpHandler {

        Map<String, String> parameters;

        public PrivateKeyHandler() {
            super();
            parameters = new HashMap<>();
        }

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(httpExchange.getRequestBody(), "utf-8"));
            String query = reader.readLine();
            parseQuery(query);

            StringBuilder response = new StringBuilder();
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

    private class HelloHttpsConfigurator extends HttpsConfigurator {

        HelloHttpsConfigurator(SSLContext sslContext) {
            super(sslContext);
        }

        @Override
        public void configure(HttpsParameters httpsParameters) {
            super.configure(httpsParameters);
            try {
                SSLContext c = SSLContext.getDefault();
                SSLEngine engine = c.createSSLEngine();
                httpsParameters.setNeedClientAuth(false);
                httpsParameters.setCipherSuites(engine.getEnabledCipherSuites());
                httpsParameters.setProtocols(engine.getEnabledProtocols());

                SSLParameters defaultSslParams = c.getDefaultSSLParameters();
                httpsParameters.setSSLParameters(defaultSslParams);
            } catch (NoSuchAlgorithmException e) {
                logger.log(Level.SEVERE, "Failed to create HTTPS port", e);
            }
        }
    }

    public static void main(String[] args) {
        HttpsHelloServer server = new HttpsHelloServer();
        server.start();
    }

}
