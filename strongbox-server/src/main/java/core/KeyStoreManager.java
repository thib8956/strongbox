package core;

import sun.misc.BASE64Encoder;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

/**
 * Add methods to manage a KeyStore
 * A KeyStoreManager contains a KeyStore and a password
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 * @see KeyStore
 */
public class KeyStoreManager {

    private static final String JCEKS = "JCEKS";
    private KeyStore keyStore;
    private String passwd;
    
/**
 * Constructor for a Keystore Manager with KeyStore type in JCEKS.
 * @param path
 * @param passwd
 * @throws GeneralSecurityException
 * @throws IOException
 * @see KeyStoreManager(String path, String keyStoreType, String passwd)
 */
    public KeyStoreManager(String path, String passwd) throws GeneralSecurityException, IOException {
        this(path, JCEKS, passwd);
    }
    
/**
 * Second constructor for a Keystore Manager. 
 * The type of the KeyStore is determinated by the input argument : KeyStoreType
 * @param path
 * @param keyStoreType
 * @param passwd
 * @throws GeneralSecurityException
 * @throws IOException
 */
    public KeyStoreManager(String path, String keyStoreType, String passwd) throws GeneralSecurityException, IOException {
        keyStore = KeyStore.getInstance(keyStoreType);
        try (FileInputStream fileInputStream = new FileInputStream(path)) {
            keyStore.load(fileInputStream, passwd.toCharArray());
        }
        this.passwd = passwd;
    }
    
/**
 * Check if the input password is equal to store password.
 * @param passwd
 * @return True if is equals or false
 */
    public Boolean checkPassword(String passwd) {
        return passwd.equals(this.passwd);
    }
 
    /**
     * Give the KeyStore instance
     * @return The KeyStore instance
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }   
    
/**
 * Get the private key link to the input argument publicKey
 * @param publicKey
 * @param passwd
 * @return The private key linked to the public key. 
 * @throws KeyStoreException
 * @throws UnrecoverableKeyException
 * @throws NoSuchAlgorithmException
 */
    public PrivateKey getPrivateKey(PublicKey publicKey, String passwd) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
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
 * Format the private key to string
 * @param pk
 * @return A string representing the private Key
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
     * Get the public key link to the b64Key input argument with the specification contained
     * @param b64Key
     * @return The Public Key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    // TODO: handle DSA keys
    public static PublicKey getPublicKey(String b64Key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        final byte[] byteKey;
        try {
            byteKey = Base64.getDecoder().decode(b64Key);
        } catch (RuntimeException e) {
            throw new InvalidKeyException(e);
        }

        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        // Get public key from base64 string
        return kf.generatePublic(X509publicKey);
    }
}
