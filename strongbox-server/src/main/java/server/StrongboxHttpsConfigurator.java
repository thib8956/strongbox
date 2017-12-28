package server;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 * Https Configurator for StrongBox server.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 * @see HttpsConfigurator
 */
class StrongboxHttpsConfigurator extends HttpsConfigurator {

    private final Logger logger = Logger.getLogger(StrongboxHttpsConfigurator.class.getName());

    /**
     * Constructor for the StrongboxHttpsConfigurator.
     * @param sslContext SSL context
     */
    StrongboxHttpsConfigurator(SSLContext sslContext) {
        super(sslContext);
    }

    /**
     * Called by the HttpsServer to configure the parameters for a https connection currently being established.
     * @param httpsParameters Set of parameters for https connection.
     * @see httpsParameters
     * @see HttpsServer
     */
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
