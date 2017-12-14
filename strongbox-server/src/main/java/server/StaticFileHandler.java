package server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @author thibaud
 *
 */
public class StaticFileHandler implements HttpHandler {

    private static final String INDEX = "index.html";
    private static final Map<String, String> MIME_TYPES = new HashMap<>();

    static {
        MIME_TYPES.put("css", "text/css");
        MIME_TYPES.put("html", "text/html");
        MIME_TYPES.put("js", "application/javascript");
    }

    private String filesystemRoot;
    private String urlPrefix;

    public StaticFileHandler(String urlPrefix, String filesystemRoot) {
        try {
            this.filesystemRoot = new File(filesystemRoot).getCanonicalPath();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        this.urlPrefix = urlPrefix;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        String method = httpExchange.getRequestMethod();
        if (! method.equals("GET")) {
            sendError(httpExchange, 501, "Unsupported method");
            return;
        }

        String requestedUrl = httpExchange.getRequestURI().getPath();
        if (requestedUrl.endsWith("/")) {
            requestedUrl += INDEX;
        }

        final File requestedFile = new File(filesystemRoot, requestedUrl).getCanonicalFile();
        FileInputStream fis;
        try {
            fis=new FileInputStream(requestedFile);
        } catch (FileNotFoundException e) {
            sendError(httpExchange, 404, "File not found");
            return;
        }

        // Set MIME type for the requested file.
        final String extension = getFileExtension(requestedFile).toLowerCase();
        String mimeType = MIME_TYPES.getOrDefault(extension, "application/octet-stream");
        httpExchange.getResponseHeaders().set("Content-Type", mimeType);
        httpExchange.sendResponseHeaders(200, requestedFile.length());
        try (OutputStream os = httpExchange.getResponseBody()) {
            copyStream(fis, os);
        }
        fis.close();
    }

    private void sendError(HttpExchange httpExchange, int code, String msg) throws IOException {
        final byte[] msgBytes = msg.getBytes("UTF-8");
        httpExchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        httpExchange.sendResponseHeaders(code, msgBytes.length);
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(msgBytes);
        }
    }

    private static void copyStream(InputStream is, OutputStream os) throws IOException {
        final byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) >= 0) {
            os.write(buf, 0, n);
        }
    }

    private static String getFileExtension(File file) {
        String name = file.getName();
        try {
            return name.substring(name.lastIndexOf(".") + 1);
        } catch (Exception e) {
            return "";
        }
    }
}
