package core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * This is an utility class which contains methods to display a key in PEM format, in the form of a base-64 string ;
 * and methods to convert a base-64 String in PEM format to a PublicKey, PrivateKey or Certificate object.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 */
public final class KeyUtils {

    private KeyUtils() {

    }


    /**
     * Format the given private key to a string in PEM format.
     * @param pk PrivateKey to format
     * @return base64 representation of the key in PEM format
     */
    public static String privateKeyToString(PrivateKey pk) {
        String s = "";
        String encodedPk = Base64.getEncoder().encodeToString(pk.getEncoded());
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
        String encodedPk = Base64.getEncoder().encodeToString(pk.getEncoded());
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
     * Clean a string from additional information.
     *
     * @param pem String to clean.
     * @return The string cleaned from additional information.
     */
    public static String stripHeaders(String pem) {
        return pem.replaceAll("-----(BEGIN|END) ((PUBLIC|PRIVATE) KEY|CERTIFICATE)-----", "");
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
