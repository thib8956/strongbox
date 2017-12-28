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
 * This class contains methods to manage a KeyStore
 * A KeyStoreManager contains a KeyStore and a password and allow to seek for key, add or remove key.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 * @see KeyStore
 */
public class KeyStoreManager {

    private static final String JCEKS = "JCEKS";
    private KeyStore keyStore;
    private String passwd;
    
/**
 * Constructor for a Keystore Manager with KeyStore type in JCEKS.
 * @param path Path of the KeyStore
 * @param passwd Password of the KeyStore
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
 * @param path Path of the KeyStore
 * @param keyStoreType Type of the KeyStore (ex: JCEKS)
 * @param passwd Password of the KeyStore
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
 * @param passwd Password to check
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
 * Look for a private key that matches the public key
 * @param publicKey User public key
 * @param passwd User password
 * @return The private key wanted if it's founded. 
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
     * Get the public key link to the b64Key input argument with the specification contained
     * @param b64Key Public key encoded in base64 in PEM format.
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
