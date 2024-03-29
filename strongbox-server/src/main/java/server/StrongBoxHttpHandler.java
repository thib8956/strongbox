package server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import core.KeyStoreManager;
import core.KeyUtils;

import java.io.*;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An HttpHandler for the StrongBox server.
 * <p>
 * Can response to a "Get" request (Giving the private key), add keys or remove some keys from the keystore.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 *
 */
class StrongBoxHttpHandler implements HttpHandler {

    private static final Logger logger = Logger.getLogger(StrongBoxHttpHandler.class.getName());
    private static final String KEYSTORE_PATH = "src/main/resources/keystore.jks";


    private final Map<String, String> parameters;
    private final Context context;

    /**
     * Constructor for the StrongBoxHttpHandler.
     * @param context Context of server
     */
    StrongBoxHttpHandler(Context context) {
        super();
        this.context = context;
        parameters = new HashMap<>();
    }

    /**
     * Handles a given request and generates an appropriate response.
     * <p>
     * Override HttpHandler.handle
     * @param httpExchange the exchange containing the request from the client and used to send the response
     * @throws IOException if an I/O error occurs
     * @see HttpExchange
     */
    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(httpExchange.getRequestBody(), StrongboxHttpsServer.ENCODING));
        String query = reader.readLine();
        parseQuery(query);

        switch (context) {
            case PKSERVER:
                handlePkserver(httpExchange);
                break;
            case ADD:
                handleAdd(httpExchange);
                break;
            case DELETE:
                handleDelete(httpExchange);
                break;
        }
    }

    /**
     * Receive client request with the public key to find and the password, and give to client the linked private key or an error.
     * @param httpExchange the exchange containing the request from the client and used to send the response
     * @throws IOException if an I/O error occurs.
     * @see HttpExchange
     */
    private void handlePkserver(HttpExchange httpExchange) throws IOException {
        StringBuilder response = new StringBuilder();

        String providedB64Key = KeyUtils.stripHeaders(parameters.get("publickey")).replaceAll("\\s", "");
        String password = parameters.get("password");

        try {
            KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
            final PublicKey publicKey = KeyUtils.publicKeyFromString(providedB64Key);

            PrivateKey privateKey;
            try {
                privateKey = manager.getPrivateKey(publicKey, password);
            } catch (UnrecoverableKeyException e) {
                //try again with empty password
                logger.log(Level.WARNING, "Empty password");
                privateKey = manager.getPrivateKey(publicKey, "");
            }

            if (privateKey == null) {
                throw new InvalidKeySpecException();
            }

            response.append("Algorithm : ").append(privateKey.getAlgorithm()).append("\n");
            response.append("Format : ").append(privateKey.getFormat()).append("\n");
            response.append(KeyUtils.privateKeyToString(privateKey));
        } catch (IOException e) {
            // Bad password
            final String msg = "The provided password is incorrect.";
            if (e.getCause() instanceof UnrecoverableKeyException) {
                response.append(msg);
            }
            logger.log(Level.WARNING, null, msg);
        } catch (InvalidKeySpecException e) {
            logger.log(Level.WARNING, "Invalid public key", e.getMessage());
            response.append("The provided public key is invalid or wasn't found in the keystore.");
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, null, e);
        }

        httpExchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(response.toString().getBytes());
        }
    }

    /**
     * Receive client request with the private key, the certificate, the alias and the password to add the key in the KeyStore.
     * @param httpExchange the exchange containing the request from the client and used to send the response.
     * @throws IOException if an I/O error occurs.
     * @see HttpExchange
     */
    private void handleAdd(HttpExchange httpExchange) throws IOException {
        String response = "The private key was successfully added to the keystore.";

        String providedB64Cert = KeyUtils.stripHeaders(parameters.get("cert")).replaceAll("\\s", "");
        String providedB64Key = KeyUtils.stripHeaders(parameters.get("privatekey")).replaceAll("\\s", "");
        String providedAlias = parameters.get("alias");
        String password = parameters.get("password");

        try {
            KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
            X509Certificate certificate = (X509Certificate) KeyUtils.certificateFromString(providedB64Cert);
            PrivateKey privateKey = KeyUtils.privateKeyFromString(providedB64Key);

            manager.addPrivateKey(providedAlias, certificate, privateKey);
        } catch (IOException e) {
            // Bad password
            final String msg = "The provided password is incorrect.";
            if (e.getCause() instanceof UnrecoverableKeyException) {
                response = msg;
            }
            logger.log(Level.WARNING, null, msg);
        } catch (CertificateException e) {
            final String msg = "The provided certificate is incorrect or empty.";
            response = msg;
            logger.log(Level.SEVERE, msg, e.getMessage());
        } catch (InvalidKeySpecException e) {
            final String msg = "The provided private key is incorrect or missing.";
            response = msg;
            logger.log(Level.SEVERE, msg, e.getMessage());
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, null, e);
        }

        httpExchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }
    
    /**
     * Receive client request with the alias and the password to delete the key from the KeyStore.
     * @param httpExchange the exchange containing the request from the client and used to send the response.
     * @throws IOException if an I/O error occurs.
     * @see HttpExchange
     */
    private void handleDelete(HttpExchange httpExchange) throws IOException {
        String providedAlias = parameters.get("alias");
        String password = parameters.get("password");
        String response = "";

        try {
            KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
            manager.deleteEntry(providedAlias);
            response = "The key corresponding to the alias " + providedAlias +
                    " was successfully deleted from the keystore.";
        } catch (IOException e) {
            // Bad password
            if (e.getCause() instanceof UnrecoverableKeyException) {
                response = "The provided password is incorrect.";
            }
        } catch (KeyStoreException e) {
            response = "The alias " + providedAlias + "was not found in the keystore.";
            logger.log(Level.WARNING, null, e);
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, null, e);
        }

        httpExchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    /**
     * Parse the query for the server.
     * @param query Query to parse
     * @throws UnsupportedEncodingException If character encoding needs to be consulted, but named character encoding is not supported
     */
    private void parseQuery(String query) throws UnsupportedEncodingException {
        if (query == null) {
            return;
        }

        final String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] param = pair.split("=");
            if (param.length < 2) {
                logger.log(Level.WARNING, "No value provided for parameter " + param[0]);
                param = new String[] {param[0], ""};
            }
            String decodedValue =  URLDecoder.decode(param[1], StrongboxHttpsServer.ENCODING);

            parameters.put(param[0], decodedValue);
        }
    }

}
