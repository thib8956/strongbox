import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;

public class KeyStoreManager {

    private String passwd;
    private KeyStore keyStore;

    public KeyStoreManager(String path, String passwd) throws GeneralSecurityException, IOException {
        this(path, "JCEKS", passwd);
    }

    private KeyStoreManager(String path, String keyStoreType, String passwd) throws GeneralSecurityException, IOException {
        this.passwd = passwd;
        keyStore = KeyStore.getInstance(keyStoreType);
        try (FileInputStream fileInputStream = new FileInputStream(path)) {
            keyStore.load(fileInputStream, passwd.toCharArray());
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public PrivateKey getPrivateKey(PublicKey publicKey) {
        return null;
    }
}
