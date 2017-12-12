package server;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HttpsHelloServer {

    private HttpsServer httpsServer;
    private Logger logger = Logger.getLogger(HttpsHelloServer.class.getName());

    public HttpsHelloServer() {
        InetSocketAddress address = new InetSocketAddress(8000);
        try {
            httpsServer = HttpsServer.create(address, 0);
            SSLContext context = SSLContext.getInstance("TLS");
            char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream("res/keystore.jks");
            ks.load(fis, password);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(ks);

            context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            httpsServer.setHttpsConfigurator(new HttpsConfigurator(context) {
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
            });

            httpsServer.createContext("/test", new HelloHandler());
            httpsServer.setExecutor(null);

        } catch (GeneralSecurityException | IOException e) {
            logger.log(Level.SEVERE, null, e);
        }
    }

    public void start() {
        httpsServer.start();
    }

    public static class HelloHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            String response = "Hello world !";

            httpExchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            httpExchange.sendResponseHeaders(200, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    public static void main(String[] args) {
        HttpsHelloServer server = new HttpsHelloServer();
        server.start();
    }
}
