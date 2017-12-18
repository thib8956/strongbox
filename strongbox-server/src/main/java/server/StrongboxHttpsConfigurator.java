package server;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

class StrongboxHttpsConfigurator extends HttpsConfigurator {

    private final Logger logger = Logger.getLogger(StrongboxHttpsConfigurator.class.getName());

    StrongboxHttpsConfigurator(SSLContext sslContext) {
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
