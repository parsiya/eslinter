package burp;

import static burp.BurpExtender.callbacks;
import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import utils.StringUtils;


/**
 * Config
 */
public class Config {

    // Transient fields are not serialized or deserialized.
    // This appears in Extender.
    final public static transient String extensionName = "ESLint for Burp";
    // This is the extension's tab name.
    final public static transient String tabName = "ESLinter";
    // Table's column names.
    final public static transient String[] lintTableColumnNames =
            new String[] {"Host", "URL", "Status", "Number of Findings"};
    // Table's column classes.
    final public static transient Class[] lintTableColumnClasses =
            new Class[] {java.lang.String.class, java.lang.String.class, java.lang.String.class,
                    java.lang.String.class // Although last column is int, we want it to be
                                           // left-aligned.
            };
    // Maximum number of characters from the URL.
    final public static transient int urlFileNameLimit = 50;
    // Default config file name.
    final public static transient String defaultConfigName = "config.json";

    // End transient fields.

    // Storage path for extracted beautified JavaScript files.
    @SerializedName("beautified-javascript-path")
    public String storagePath = "";

    // Where ESLint results are stored.
    @SerializedName("eslint-output-path")
    public String eslintOutputPath = "";

    // ESLint binary full path. [path]/node_modules/.bin/eslint
    @SerializedName("eslint-command-path")
    public String eslintCommandPath = "";

    // Path to the ESLint configuration file.
    @SerializedName("eslint-config-path")
    public String eslintConfigPath = "";

    // Full path to the js-beautify binary/command. [path]/node_modules/.bin/eslint
    @SerializedName("jsbeautify-command-path")
    public String jsBeautifyCommandPath = "";

    // Full path to the sqlite database file. It will be created if it does not
    // exist.
    @SerializedName("database-path")
    public String dbPath = "";

    // If true, only in-scope requests will be processed.
    @SerializedName("only-process-in-scope")
    public boolean processInScope = false;

    // If true, requests containing JavaScript will be highlighted in history.
    @SerializedName("highlight")
    public boolean highlight = false;

    // Only lint requests made by these tools. The names here must be the same
    // as the getToolName column (case-insensitive):
    // | ToolFlag | getToolName |
    // |----------------|-------------|
    // | TOOL_SUITE | Suite |
    // | TOOL_TARGET | Target |
    // | TOOL_PROXY | Proxy |
    // | TOOL_SPIDER | Scanner |
    // | TOOL_SCANNER | Scanner |
    // | TOOL_INTRUDER | Intruder |
    // | TOOL_REPEATER | Repeater |
    // | TOOL_SEQUENCER | Sequencer |
    // | TOOL_DECODER | null |
    // | TOOL_COMPARER | null |
    // | TOOL_EXTENDER | Extender |
    @SerializedName("process-tool-list")
    public String[] processToolList = new String[] {"Proxy", "Scanner", "Repeater"};

    // If set to true, the extension will print extra information. This can be
    // used for troubleshooting.
    public boolean debug = true;

    // Maximum number of linting threads.
    @SerializedName("number-of-linting-threads")
    public int numLintThreads = 3;

    // How many seconds to wait for a linting task to complete. Increase this if
    // you are beautifying and linting huge files.
    @SerializedName("linting-timeout")
    public int lintTimeout = 60;

    // Maximum number of request/response processing threads.
    // These tasks are light-weight.
    @SerializedName("number-of-request-threads")
    public int numRequestThreads = 10;

    // Threadpool shutdown timeout in seconds. How many seconds to wait before
    // shutting down threadpools when unloading the extension.
    @SerializedName("threadpool-timeout")
    public int threadpoolTimeout = 10;

    // The number of seconds the lint task sleeps between reading new lint tasks
    // from the database.
    @SerializedName("lint-task-delay")
    public int lintTaskDelay = 10;

    // Update table frequency in seconds. The number of seconds the updat table
    // task sleeps between updates.
    @SerializedName("update-table-delay")
    public int updateTableDelay = 5;

    // Maximum size of JavaScript to process in KBs.
    @SerializedName("maximum-js-size")
    public int jsMaxSize = 10000;

    /**
     * JavaScript MIME types. Search for "text/javascript" here
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types Only
     * "text/javascript" is supposedly supported but who knows. Should be entered as lowercase here.
     * Burp returns "script" for JavaScript.
     */
    @SerializedName("js-mime-types")
    public String[] jsTypes = new String[] {"application/javascript", "application/ecmascript",
            "application/x-ecmascript", "application/x-javascript", "text/javascript",
            "text/ecmascript", "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
            "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "text/jscript",
            "text/livescript", "text/x-ecmascript", "text/x-javascript", "script" // This is what
                                                                                  // Burp returns as
                                                                                  // the MIMEType if
                                                                                  // it detects js.
    };

    // File extensions that might contain JavaScript.
    @SerializedName("javascript-file-extensions")
    public String[] fileExtensions = new String[] {"js", "javascript"};

    // Content-Types that might contain scripts, the JavaScript inside these
    // will be extracted and used.
    // Should be entered as lowercase here.
    @SerializedName("contains-javascript")
    public String[] containsScriptTypes = new String[] {"text/html", "application/xhtml+xml" // XHTML,
                                                                                             // be
                                                                                             // sure
                                                                                             // to
                                                                                             // remove
                                                                                             // the
                                                                                             // CDATA
                                                                                             // tags.
    };

    /**
     * Removable headers. These headers will be removed from the requests. The change will not
     * appear in Burp history but the outgoing request will not have these headers.
     */
    @SerializedName("removable-headers")
    public String[] headersToRemove = new String[] {"If-Modified-Since", "If-None-Match"};

    // Convert the config to JSON.
    public String toString() {
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(this);
    }

    // No-args constructor for Gson.
    public Config() {
    }

    // Creates a config object from the json string.
    public static Config configBuilder(String json) throws JsonSyntaxException {
        return new Gson().fromJson(json, Config.class);
    }

    // Writes the config files to file.
    public void writeToFile(File path) throws IOException {
        FileUtils.writeStringToFile(path, toString(), StringUtils.UTF8);
    }

    // 1. Converts the Config object to a json string.
    // 2. Encodes it in base64.
    // 3. Saves the config to extension settings.
    public void saveConfigToExtensionSettings() {
        // 1. Convert to string.
        String cfgStr = toString();
        // 2. Base64 encode.
        String cfgBase64 = StringUtils.base64Encode(cfgStr);
        // 3. Save it to extension settings.
        callbacks.saveExtensionSetting("config", cfgBase64);
    }

    // Creates a new config from the json string and returns it. Also waits for
    // the threadpool to shutdown, closes the DB connection and establishes a
    // connection to the new DB set in the new config file.
    public static Config loadConfig(String json) throws SQLException, IOException {
        // Unload the extension, because we are loading a new config.
        BurpExtender.unloadExtension();
        // Read the json string and create a new config.
        Config cfg = configBuilder(json);
        // Connect to the new database file.
        BurpExtender.databaseConnect(cfg.dbPath);
        // Save the config file in extension settings.
        cfg.saveConfigToExtensionSettings();
        return cfg;
    }

    // Returns the full path to the default config file.
    public static String getDefaultConfigFullPath(){
        // Get the extension jar path.
        String jarPath = callbacks.getExtensionFilename();
        // Get the parent directory of the jar path.
        String jarDirectory = StringUtils.getParentDirectory(jarPath);

        // Create the full path for the default config file.
        // jarDirectory/Config.defaultConfigName.
        return FilenameUtils.concat(jarDirectory, defaultConfigName);
    }
}