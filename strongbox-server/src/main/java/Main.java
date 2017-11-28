import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {

    public static void createKeyStore(String filename) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "password".toCharArray();
        ks.load(null, password);

        // Store away the keystore.
        FileOutputStream fos = new FileOutputStream(filename);
        ks.store(fos, password);
        fos.close();
    }

    public static void main(String[] args) {
        /*try {
            InetSocketAddress address = new InetSocketAddress(InetAddress.getLocalHost(), 8000);
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            SSLContext context = SSLContext.getInstance("TLS");

            char[] passwd = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            // Open the keystore file.
            FileInputStream fis = new FileInputStream("test.jks");
            ks.load(fis, passwd);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(ks, passwd);

        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }*/
        try {
            createKeyStore("kssrv.ks");
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }
}
