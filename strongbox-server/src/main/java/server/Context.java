package server;

/**
 * Enumeration of context that can be used.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
 *
 */
public enum Context {

    MAIN("/"), PKSERVER("/pkserver"), ADD("/pkserver/add"), DELETE("/pkserver/delete");

    public final String name;

    Context(String name) {
        this.name = name;
    }
}
