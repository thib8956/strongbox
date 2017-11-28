import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executor;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * Une classe implémentant un service Hello personnalisé
 * sécurisé par SSL/TLS
 * @author Patrick Guichet
 */
public class HttpsHelloServer {
    ////////////////////////////////////////////////////////
    // Initialisation des propriétés systèmes nécessaires
    // à l'établissement d'un contexte SSL
    static {
        System.setProperty("javax.net.ssl.keyStore", "kssrv.ks");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.debug", "all");
    }

    /**
     * Classe implémentant le gestionnaire de requètes vers le service hello
     */
    static class HelloHandler implements HttpHandler {

        private static final String PLAIN_HELLO = "<h1 align='center'>HELLO</h1>";
        private static final String PERSONNAL_HELLO = "<h1 align='center'>HELLO %s %s</h1>";

        /**
         * Méthode de gestion des requètes vers le service hello
         * @param he l'objet encapsulant la requète et la réponse
         * @throws IOException si le traitement de la requète ou de la réponse échoue
         */
        @Override
        public void handle(HttpExchange he) throws IOException {
            // récupération des paramètres de requètes
            String query = he.getRequestURI().getQuery();
            // récupération des en-têtes de la réponse HTTP
            Headers responseHeaders = he.getResponseHeaders();
            responseHeaders.set("Content-Type", "text/html");
            // Fabrication de la réponse (ordinaire ou personnalisée)
            String response = PLAIN_HELLO;
            if (query != null) {
                response = parseHelloQuery(query);
            }
            byte[] responseBytes = response.getBytes();
            // préparation de la réponse
            he.sendResponseHeaders(200, responseBytes.length);
            try (OutputStream out = he.getResponseBody()) {
                out.write(responseBytes);
                out.flush();
            }
        }

        /**
         * Méthode d'aide pour la récupération des valeurs des paramètres nom et prenom
         * @param query les paramètres de requète :
         * normalement une chaîne de la forme nom = ****&prenom=****
         * @return le message d'accueil personnalisé
         */
        private static String parseHelloQuery(String query) {
            String[] params = query.split("\\s*\\&\\s*");
            // récupération prénom
            String prenom = params[1].split("\\s*=\\s*")[1];
            // récupération nom
            String nom = params[0].split("\\s*=\\s*")[1];
            return String.format(PERSONNAL_HELLO, prenom, nom);
        }
    }

    /**
     * Classe gérant l'ordonnancement des réactions aux requètes
     * Ici un nouveau thread est créé pour le traitement de chaque requète
     */
    static class ThreadPerTaskExecutor implements Executor {

        /**
         * Méthode implémentant la stratégie d'exécution d'une nouvelle requète
         * @param command le Runnable à exécuter
         */
        @Override
        public void execute(Runnable command) {
            // Instancier un nouveau thread dédié à l'exécution de ce Runnable
            // et le démarrer
            new Thread(command).start();
        }
    }
    // le contexte du service
    private static final String CONTEXT = "/hello";

    /**
     * Création d'une instance du serveur
     * @param host le nom de l'hôte hébergeant le service
     * @param port le numéro de port associé au service hello
     * @throws IOException si la création du serveur échoue
     */
    private HttpsHelloServer(String host, int port) throws IOException, GeneralSecurityException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(host, port), 0);
        // Association du contexte au handler chargé de traiter les requètes
        server.createContext(CONTEXT, new HelloHandler());
        // Configuration du contexte SSL
        server.setHttpsConfigurator(new HttpsConfigurator(SSLContext.getDefault()));
        // Configuration de l'exécuteur traitant les réponses
        server.setExecutor(new ThreadPerTaskExecutor());
        // Lancement du serveur
        server.start();
        System.out.println("En attente de connection!..");
    }

    /**
     * Lancement de la classe
     * @param args les éventuels arguments transmis en ligne de commande
     */
    public static void main(String[] args) {
        try {
            HttpsHelloServer httpsHelloServer = new HttpsHelloServer("localhost", 7878);
        } catch (IOException | GeneralSecurityException ex) {
            Logger.getLogger(HttpsHelloServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

