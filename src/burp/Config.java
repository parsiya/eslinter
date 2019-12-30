package burp;

/**
 * Config
 */
public class Config {

    // This appears in Extender.
    public static String ExtensionName = "ESLint for Burp";
    // This is the extension's tab name.
    public static String TabName = "ESLinter";

    // Storage path for extracted JavaScript files.
    public static String StoragePath = "C:\\Users\\IEUser\\Desktop\\eslint\\";

    // ESLint installation path.
    public static String ESLintBinaryPath = "C:\\Users\\IEUser\\Desktop\\git\\eslint-security-scanner-configs\\node_modules\\.bin\\eslint";

    // Config path.
    public static String ESLintConfigPath = "C:\\Users\\IEUser\\Desktop\\git\\eslint-security-scanner-configs\\eslintrc-light.js";

    // Where ESLint results are stored.
    public static String ESLintOutputPath = "C:\\Users\\IEUser\\Desktop\\eslint\\output\\";

    // Maximum number of threads.
    public static int NumberOfThreads = 3;

    /**
     * JavaScript MIME types.
     * Search for "text/javascript" here
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
     * Only "text/javascript" is supposedly supported but who knows.
     * Should be entered as lowercase here.
     */
    public static String[] JSTypes = new String[] {
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
        "text/x-javascript",
        "script" // This is what Burp returns as the MIMEType if it detects js.
    };

    // File extensions.
    public static String[] FileExtensions = new String[] {
        "js",
        "javascript"
    };

    // Content-Types that might contain scripts.
    // Should be entered as lowercase here.
    public static String[] ContainsScriptTypes = new String[] {
        "text/html",
        "application/xhtml+xml" // XHTML, be sure to remove the CDATA tags.
    };

    /**
     * Removable headers.
     * These headers will be removed from the requests. The change will not
     * appear in Burp history but the outgoing request will not have these
     * headers.
     */
    public static String[] RemovedHeaders = new String[] {
        "If-Modified-Since",
        "If-None-Match"
        // TODO Find more headers.
    };
}