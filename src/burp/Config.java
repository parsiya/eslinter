package burp;

import java.io.File;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import org.apache.commons.io.FileUtils;


/**
 * Config
 */
public class Config {

    // Transient fields are not serialized or deserialized.
    // This appears in Extender.
    final public static transient String ExtensionName = "ESLint for Burp";
    // This is the extension's tab name.
    final public static transient String TabName = "ESLinter";

    final public static transient String[] lintTableColumnNames = new String[] {
        "Host", "URL", "Status", "Number of Findings"
    };

    final public static transient Class[] lintTableColumnClasses = new Class[] {
        java.lang.String.class, java.lang.String.class,
        java.lang.Integer.class, java.lang.String.class
    };

    // End final transient fields.

    // Storage path for extracted beautified JavaScript files.
    @SerializedName("beautified-javascript-path")
    public String StoragePath = "";

    // Where ESLint results are stored.
    @SerializedName("eslint-output-path")
    public String ESLintOutputPath = "";

    // ESLint binary path. E.g., node_modules\.bin\eslint
    @SerializedName("eslint-binary-path")
    public String ESLintBinaryPath = "";

    // Path to the ESLint configuration file.
    @SerializedName("eslint-config-path")
    public String ESLintConfigPath = "";

    // If true, only in-scope requests will be processed.
    @SerializedName("only-process-in-scope")
    public boolean processInScope = false;

    // If true, requests containing JavaScript will be highlighted in history.
    @SerializedName("highlight")
    public boolean highlight = false;

    // Only lint requests made by these tools. The names here must be the same
    // as what is defined in the getToolName column (case-insensitive):
    // | ToolFlag       | getToolName |
    // |----------------|-------------|
    // | TOOL_SUITE     | Suite       |
    // | TOOL_TARGET    | Target      |
    // | TOOL_PROXY     | Proxy       |
    // | TOOL_SPIDER    | Scanner     |
    // | TOOL_SCANNER   | Scanner     |
    // | TOOL_INTRUDER  | Intruder    |
    // | TOOL_REPEATER  | Repeater    |
    // | TOOL_SEQUENCER | Sequencer   |
    // | TOOL_DECODER   | null        |
    // | TOOL_COMPARER  | null        |
    // | TOOL_EXTENDER  | Extender    |
    @SerializedName("process-tool-list")
    public String[] processToolList = new String[] {
        "Proxy",
        "Scanner",
        "Repeater"
    };

    // Maximum number of threads.
    @SerializedName("number-of-threads")
    public int NumberOfThreads = 3;

    /**
     * JavaScript MIME types.
     * Search for "text/javascript" here
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
     * Only "text/javascript" is supposedly supported but who knows.
     * Should be entered as lowercase here.
     */
    @SerializedName("js-mime-types")
    public String[] JSTypes = new String[] {
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

    // File extensions that might contain JavaScript.
    @SerializedName("javascript-file-extensions")
    public String[] FileExtensions = new String[] {
        "js",
        "javascript"
    };

    // Content-Types that might contain scripts, the JavaScript inside these
    // will be extracted and used.
    // Should be entered as lowercase here.
    @SerializedName("contains-javascript")
    public String[] ContainsScriptTypes = new String[] {
        "text/html",
        "application/xhtml+xml" // XHTML, be sure to remove the CDATA tags.
    };

    /**
     * Removable headers.
     * These headers will be removed from the requests. The change will not
     * appear in Burp history but the outgoing request will not have these
     * headers.
     */
    @SerializedName("removable-headers")
    public String[] RemovedHeaders = new String[] {
        "If-Modified-Since",
        "If-None-Match"
        // TODO Find more headers.
    };

    // If set to true, the extension will print extra information. This can be
    // used for troubleshooting.
    public boolean debug = true;

    public String toString() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(this);
    }

    // No-args constrcutor for Gson.
    public Config() {}

    // Will this come and kick us in the butt later?
    public static Config configBuilder(String json) {
        return new Gson().fromJson(json, Config.class);
    }

    // Writes the config files to file.
    public void writeToFile(File path) throws IOException {

        FileUtils.writeStringToFile(path, toString(), "UTF-8");
    }
}