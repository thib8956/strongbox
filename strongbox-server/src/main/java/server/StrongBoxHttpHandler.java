package server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import core.KeyStoreManager;

import java.io.*;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An HttpHandler for the StrongBox server.
 *
 * Can response to a "Get" request (Giving the private key), add keys or remove some keys.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 *
 */
class StrongBoxHttpHandler implements HttpHandler {

    private static final Logger logger = Logger.getLogger(StrongBoxHttpHandler.class.getName());
    private static final String KEYSTORE_PATH = "src/main/resources/keystore.jks";


    private Map<String, String> parameters;
    private Context context;

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
     *
     * Override HttpHandler.handle
     * @param httpExchange the exchange containing the request from the client and used to send the response
     * @throws IOException If an I/O error occurs
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

        String providedB64Key = stripHeaders(parameters.get("publickey")).replaceAll("\\s", "");
        String password = parameters.get("password");

        try {
            KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
            final PublicKey publicKey = KeyStoreManager.publicKeyFromString(providedB64Key);

            final PrivateKey privateKey = manager.getPrivateKey(publicKey, "");
            if (privateKey == null) {
                throw new InvalidKeyException();
            }

            response.append("Algorithm : ").append(privateKey.getAlgorithm()).append("\n");
            response.append("Format : ").append(privateKey.getFormat()).append("\n");
            response.append(KeyStoreManager.privateKeyToString(privateKey));
        } catch (IOException e) {
            // Bad password
            if (e.getCause() instanceof UnrecoverableKeyException) {
                response.append("The provided password is incorrect.");
            }
            logger.log(Level.WARNING, null, e);
        } catch (InvalidKeyException e) {
            logger.log(Level.WARNING, "Invalid public key", e);
            response.append("The provided public key is invalid or wasn't found in the keystore.");
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, null, e);
        }

        httpExchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(response.toString().getBytes());
        }
    }

    private void handleAdd(HttpExchange httpExchange) throws IOException {
        String response = "The private key was successfully added to the keystore.";

        String providedB64Cert = stripHeaders(parameters.get("cert")).replaceAll("\\s", "");
        String providedB64Key = stripHeaders(parameters.get("privatekey")).replaceAll("\\s", "");
        String providedAlias = parameters.get("alias");
        String password = parameters.get("password");

        try {
            KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
            X509Certificate certificate = (X509Certificate) KeyStoreManager.certificateFromString(providedB64Cert);
            PrivateKey privateKey = KeyStoreManager.privateKeyFromString(providedB64Key);

            manager.addPrivateKey(providedAlias, certificate, privateKey);
        } catch (IOException e) {
            // Bad password
            if (e.getCause() instanceof UnrecoverableKeyException) {
                response = "The provided password is incorrect.";
            }
            logger.log(Level.WARNING, null, e);
        } catch (GeneralSecurityException e) {
            logger.log(Level.WARNING, null, e);
        }

        httpExchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    private void handleDelete(HttpExchange httpExchange) throws IOException {
        String providedAlias = parameters.get("alias");
        String password = parameters.get("password");
        String response = "";

        try {
            KeyStoreManager manager = new KeyStoreManager(KEYSTORE_PATH, password);
            manager.deleteEntry(providedAlias);
            response = "The key corresponding to the alias " + providedAlias +
                    " was sucessfully deleted from the keystore.";
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

        final String[] pairs = query.split("[&]");
        for (String pair : pairs) {
            final String[] param = pair.split("[=]");
            String decodedValue =  URLDecoder.decode(param[1], StrongboxHttpsServer.ENCODING);

            parameters.put(param[0], decodedValue);
        }
    }

    /**
     * Clean a string from additionnal information.
     * @param pem String to clean.
     * @return The string cleaned from additionnal information.
     */
    private String stripHeaders(String pem) {
        return pem.replaceAll("-----(BEGIN|END) ((PUBLIC|PRIVATE) KEY|CERTIFICATE)-----", "");
    }
}
