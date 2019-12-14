package burp;

/**
 * Config
 */
public class Config {

    // This appears in Extender.
    public static String ExtensionName = "ESLint for Burp";
    // This is the extension's tab name.
    public static String TabName = "ESLinter";


    /**
     * JavaScript MIME types.
     * Search for "text/javascript" here
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
     * Only "text/javascript" is supposedly supported but who knows.
     */
    public static String[] JSMIMETypes = new String[] {
        "application/javascript",
        "application/ecmascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/javascript",
        "text/ecmascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript"
    };

    // File extensions.
    public static String[] FileExtensions = new String[] {
        "js",
        "javascript"
    };

    // Removable headers.
    // These headers will be removed from the requests. The change will not
    // appear in Burp history but the outgoing request will not have these
    // headers.
    public static String[] RemovedHeaders = new String[] {
        "If-Modified-Since",
        "If-None-Match"
        // TODO Find more headers.
    };
}