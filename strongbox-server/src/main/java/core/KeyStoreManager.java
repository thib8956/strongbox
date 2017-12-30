package core;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class contains methods to manage a KeyStore
 * A KeyStoreManager contains a KeyStore and a password and allow to seek for key, add or remove key.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 * @see KeyStore
 */
public class KeyStoreManager {

    private static final Logger logger = Logger.getLogger(KeyStoreManager.class.getName());

    private static final String JCEKS = "JCEKS";
    private String path;
    private KeyStore keyStore;
    private String password;

    /**
     * Constructor for a Keystore Manager with KeyStore type in JCEKS.
     * @param path Path of the KeyStore
     * @param password Password of the KeyStore
     * @throws GeneralSecurityException if a security manager exists and its checkRead method denies read access to the file.
     * @throws IOException if the file does not exist, is a directory rather than a regular file, or for some other reason cannot be opened for reading.
     * @see #KeyStoreManager(String path, String keyStoreType, String password)
     */
    public KeyStoreManager(String path, String password) throws GeneralSecurityException, IOException {
        this(path, JCEKS, password);
    }

    /**
     * Second constructor for a Keystore Manager.
     * The type of the KeyStore is determinated by the input argument : KeyStoreType
     * @param path Path of the KeyStore
     * @param keyStoreType Type of the KeyStore (ex: JCEKS)
     * @param password Password of the KeyStore
     * @throws GeneralSecurityException if a security manager exists and its checkRead method denies read access to the file.
     * @throws IOException if the file does not exist, is a directory rather than a regular file, or for some other reason cannot be opened for reading.
     * @see SecurityManager#checkRead(java.lang.String)
     */
    public KeyStoreManager(String path, String keyStoreType, String password) throws GeneralSecurityException, IOException {
        this.path = path;
        this.password = password;
        keyStore = KeyStore.getInstance(keyStoreType);
        try (FileInputStream fileInputStream = new FileInputStream(path)) {
            keyStore.load(fileInputStream, password.toCharArray());
        }
    }

    /**
     * Give the KeyStore instance
     * @return The KeyStore instance
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Look for a private key that matches the public key
     * @param publicKey User public key
     * @param passwd User password
     * @return The private key wanted if it's founded.
     * @throws KeyStoreException if the keystore has not been initialized (loaded).
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., the given password is wrong).
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     */
    public PrivateKey getPrivateKey(PublicKey publicKey, String passwd) throws KeyStoreException,
            UnrecoverableKeyException, NoSuchAlgorithmException {
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String currentAlias = aliases.nextElement();
            final Certificate certificate = keyStore.getCertificate(currentAlias);
            final byte[] encodedKey = certificate.getPublicKey().getEncoded();
            if (Arrays.equals(publicKey.getEncoded(), encodedKey)) {
                return (PrivateKey) keyStore.getKey(currentAlias, passwd.toCharArray());
            }
        }
        // No private key found.
        return null;
    }

    /**
     * Add a private key to the KeyStore with its alias and certificate.
     * @param alias Alias of the private key.
     * @param cert Certificate of the private key.
     * @param privateKey The private key.
     * @throws KeyStoreException if the keystore has not been initialized (loaded), the given key cannot be protected,
     * or this operation fails for some other reason.
     * @throws IOException if some I/O problem occur.
     * @throws CertificateException if some certificate problem occur.
     */
    public void addPrivateKey(String alias, Certificate cert, PrivateKey privateKey) throws KeyStoreException,
            IOException, CertificateException {
        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{cert});
        saveKeystore();
    }

    /**
     * Delete a private key by its alias
     * @param alias Alias of the key to delete.
     * @throws KeyStoreException if the keystore has not been initialized, or if the entry cannot be removed.
     * @throws IOException if some I/O problem occur.
     * @throws CertificateException if some certificate problem occur.
     */
    public void deleteEntry(String alias) throws KeyStoreException, IOException {
        if (! keyStore.containsAlias(alias)) {
            throw new KeyStoreException("The alias " + alias + "was not found in the keystore.");
        }
        keyStore.deleteEntry(alias);

        try {
            saveKeystore();
        } catch (CertificateException ignore) {
            // This should never happen when deleting an entry.
        }
    }

    /**
     * Stores this keystore to the private member class path, and protects its integrity with the private member class password.
     * @throws IOException if there was an I/O problem with data
     * @throws CertificateException if any of the certificates included in the keystore data could not be stored
     */
    private void saveKeystore() throws IOException, CertificateException {
        // store away the keystore
        try (FileOutputStream fos = new FileOutputStream(path)) {
            keyStore.store(fos, password.toCharArray());
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, null, e);
        } catch (KeyStoreException e) {
            logger.log(Level.SEVERE, "The keystore has not been initialized.", e);
        }
    }

}
