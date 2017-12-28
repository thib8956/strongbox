package server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is used to serve static files as html, javascript, css…
 * 
 * These files are stored in the directory designated by filesystemRoot.
 * @author Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser
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
    
/**
 * Constructor for a StaticFileHandler. 
 * 
 * Only files under filesystemRoot directory will be served to the client.
 * @param filesystemRoot The root directory in the filesystem.
 */
    public StaticFileHandler(String filesystemRoot) {
        try {
            this.filesystemRoot = new File(filesystemRoot).getCanonicalPath();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Manage request.
     * 
     * Support only GET request.
     * 
     * Send the file on the response stream contains in the httpExchange input argument.
     * @param httpExchange the exchange containing the request from the client and used to send the response
     * @throws IOException
     * @see httpExchange
     */
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
            fis = new FileInputStream(requestedFile);
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
    
/**
 * Use the inputStream of the httpExchange input argument to write the error code and the message.
 * @param httpExchange the exchange containing the request from the client and used to send the response
 * @param code Error code to send.
 * @param msg Message to send.
 * @throws IOException
 * @see httpExchange
 */
    private void sendError(HttpExchange httpExchange, int code, String msg) throws IOException {
        final byte[] msgBytes = msg.getBytes("UTF-8");
        httpExchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        httpExchange.sendResponseHeaders(code, msgBytes.length);
        try (OutputStream os = httpExchange.getResponseBody()) {
            os.write(msgBytes);
        }
    }
    
/**
 * Take bytes from an InputStream to write them on the OutputStream.
 * @param is Stream to copy
 * @param os Stream where to copy
 * @throws IOException
 */
    private static void copyStream(InputStream is, OutputStream os) throws IOException {
        final byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) >= 0) {
            os.write(buf, 0, n);
        }
    }
    
/**
 * Give the file extension
 * @param file File wich we whant the extention.
 * @return String corresponding to the file input argument extension.
 */
    private static String getFileExtension(File file) {
        String name = file.getName();
        try {
            return name.substring(name.lastIndexOf(".") + 1);
        } catch (Exception e) {
            return "";
        }
    }
}
