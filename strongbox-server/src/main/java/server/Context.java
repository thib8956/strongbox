package server;

/**
 * Enumeration of used contexts. Each context corresponds to a specific action of the server.
 *<p>
 * MAIN : main context, to show the web interface to the client.
 * PKSERVER : to search a key in the keystore
 * ADD : to add a key in the keystore
 * DELETE : to delete a key from the keystore.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 */
public enum Context {

    MAIN("/"), PKSERVER("/pkserver"), ADD("/pkserver/add"), DELETE("/pkserver/delete");

    public final String name;

    Context(String name) {
        this.name = name;
    }
}
