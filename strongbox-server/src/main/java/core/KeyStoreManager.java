package core;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

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

    public Iterable<Certificate> geyCertificates() throws KeyStoreException {
        final ArrayList<Certificate> certificates = new ArrayList<>();
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            certificates.add(keyStore.getCertificate(alias));
        }

        return certificates;
    }
}
