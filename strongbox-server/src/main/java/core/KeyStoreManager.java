package core;

import sun.misc.BASE64Encoder;
import sun.rmi.runtime.Log;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
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
	 * Add a private key to the KeyStore with it's alias and certificate.
	 * @param alias Alias of the private key.
	 * @param cert Certificate of the private key.
	 * @param privateKey The private key.
	 * @throws KeyStoreException if the keystore has not been initialized (loaded), the given key cannot be protected, or this operation fails for some other reason.
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
    public void deleteEntry(String alias) throws KeyStoreException, IOException, CertificateException {
        keyStore.deleteEntry(alias);
        saveKeystore();
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

    /**
     * Format the given private key to a string in PEM format.
     * @param pk PrivateKey to format
     * @return base64 representation of the key in PEM format
     */
    public static String privateKeyToString(PrivateKey pk) {
        String s = "";
        String encodedPk = new BASE64Encoder().encode(pk.getEncoded());
        s += "-----BEGIN PRIVATE KEY-----\n";
        s += encodedPk + '\n';
        s += "-----END PRIVATE KEY-----\n";
        return s;
    }

    /**
     * Format the given public key to a string in PEM format.
     * @param pk PublicKey to format
     * @return base64 representation of the key in PEM format
     */
    public static String publicKeyToString(PublicKey pk) {
        String s = "";
        String encodedPk = new BASE64Encoder().encode(pk.getEncoded());
        s += "-----BEGIN PUBLIC KEY-----\n";
        s += encodedPk + '\n';
        s += "-----END PUBLIC KEY-----\n";
        return s;
    }

    /**
     * Get the public key link to the b64Key input argument with the specification contained
     * @param b64Key Public key encoded in base64 in PEM format.
     * @return The Public Key
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactorySpi implementation for the specified algorithm.
     * @throws InvalidKeySpecException if the given key specification is inappropriate for this key factory to produce a public key.
     * @throws InvalidKeyException if b64Key is not in valid Base64 scheme.
     */
    public static PublicKey publicKeyFromString(String b64Key) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException {
        final byte[] keyBytes = decodeKey(b64Key);

        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey key;
        try {
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePublic(keySpec);
        } catch (InvalidKeySpecException ignore) {
            final KeyFactory kf = KeyFactory.getInstance("DSA");
            key = kf.generatePublic(keySpec);
        }

        return key;
    }
    
	/**
	* Get the certificate link to the b64Cert input argument
	* @param b64Cert Certificate encoded in base64 in PEM format
	* @return The certificate
	* @throws CertificateException if error while decoding Base64 input
	*/
    public static Certificate certificateFromString(String b64Cert) throws CertificateException {
        final byte[] byteCert;
        try {
            byteCert = Base64.getDecoder().decode(b64Cert);
        } catch (RuntimeException e) {
            // Error while decoding Base64 input
            throw new CertificateException();
        }

        InputStream is = new ByteArrayInputStream(byteCert);
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        return factory.generateCertificate(is);
    }
    
    /**
     * Get the private key link to the b64Key input argument with the specification contained
     * @param b64Key Private key encoded in base64 in PEM format.
     * @return The private key
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactorySpi implementation for the specified algorithm.
     * @throws InvalidKeySpecException if the given key specification is inappropriate for this key factory to produce a public key.
     * @throws InvalidKeyException if error while decoding Base64 input
     */
    public static PrivateKey privateKeyFromString(String b64Key) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException {
        final byte[] keyBytes = decodeKey(b64Key);

        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey key;
        try {
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException ignore) {
            final KeyFactory kf = KeyFactory.getInstance("DSA");
            key = kf.generatePrivate(keySpec);
        }

        return key;
    }

    /**
     * Decodes a Base64 encoded String into a newly-allocated byte array.
     * @param b64Key Key encoded in base64 in PEM format.
     * @return A byte array containing the decoded bytes.
     * @throws InvalidKeyException if error while decoding Base64 input
     */
    private static byte[] decodeKey(String b64Key) throws InvalidKeyException {
        try {
            return Base64.getDecoder().decode(b64Key);
        } catch (RuntimeException e) {
            // Error while decoding Base64 input
            throw new InvalidKeyException();
        }
    }
}
