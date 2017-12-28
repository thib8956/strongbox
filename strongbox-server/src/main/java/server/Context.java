package server;

public enum Context {

    MAIN("/"), PKSERVER("/pkserver"), ADD("/pkserver/add"), DELETE("/pkserver/delete");

    public final String name;

    Context(String name) {
        this.name = name;
    }
}
