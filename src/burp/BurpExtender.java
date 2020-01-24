package burp;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import database.Database;
import gui.BurpTab;
import lint.Metadata;
import lint.ProcessLintQueue;
import lint.ProcessRequestTask;
import lint.ProcessResponseTask;
import lint.UpdateTableTask;
import utils.BurpLog;
import utils.ReqResp;
import utils.StringUtils;

public class BurpExtender implements
    IBurpExtender, ITab, IHttpListener, IExtensionStateListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static Config extensionConfig;
    public static BurpLog log;
    public static BurpTab mainTab;
    public static Database db;
    public static boolean keepThread;

    private static ExecutorService pool;
    private static ExecutorService requestPool;
    private static ExecutorService responsePool;
    private static Thread processThread;
    private static Thread updateThread;

    private static int threadNum = 10;
    private static int timeout = 60;
    

    /**
     * Implement IBurpExtender.
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks burpCallbacks) {

        callbacks = burpCallbacks;
        helpers = callbacks.getHelpers();
        // Set the extension name.
        callbacks.setExtensionName(Config.extensionName);

        // Create the logger.
        log = new BurpLog(true);

        // Use the default config. This is needed in case there is no config
        // saved or there is no default config file.
        extensionConfig = getDefaultConfig();

        // Search for the default config file and load it if it exists.
        loadDefaultConfigFile(Config.defaultConfigName);

        // Load saved config from extension settings (if any).
        loadSavedConfig();

        // Set the debug flag from the loaded config.
        log.setDebugMode(extensionConfig.debug);

        // Configure the process request and response threadpools.
        requestPool = Executors.newFixedThreadPool(threadNum);
        responsePool = Executors.newFixedThreadPool(threadNum);

        // Configure the beautify executor service.
        pool = Executors.newFixedThreadPool(extensionConfig.numberOfThreads);
        log.debug("Using %d threads.", extensionConfig.numberOfThreads);
        // Create the ProcessLintQueue object and assigned the threadpool.
        ProcessLintQueue linter = new ProcessLintQueue(extensionConfig, pool);

        keepThread = true;
        // Start processing.
        processThread = new Thread(linter);
        processThread.start();

        // Create the table update thread.
        UpdateTableTask updater = new UpdateTableTask(extensionConfig);
        updateThread = new Thread(updater);
        updateThread.start();

        log.debug("Started both threads.");

        // Create the main tab.
        mainTab = new BurpTab();
        log.debug("Created the main tab.");
        callbacks.customizeUiComponent(mainTab.panel);

        // Connect to the database (or create it if it doesn't exist).
        databaseConnect(extensionConfig.dbPath);

        // Add the tab to Burp.
        callbacks.addSuiteTab(BurpExtender.this);
        // Register the listener.
        callbacks.registerHttpListener(BurpExtender.this);
        // Register the extension state listener to handle extension unload.
        callbacks.registerExtensionStateListener(BurpExtender.this);

        log.debug("Loaded the extension. End of registerExtenderCallbacks.");
    }

    @Override
    public String getTabCaption() {
        return Config.tabName;
    }

    @Override
    public Component getUiComponent() {
        // Return the tab here.
        return mainTab.panel;
    }

    @Override
    public void processHttpMessage(final int toolFlag, final boolean isRequest, IHttpRequestResponse requestResponse) {

        if (requestResponse == null) return;

        // If it's a request, spawn a new thread and process it. We do not need
        // to worry about responses being processed before their requests
        // because the response will only arrive after the request is processed
        // and sent out. D'oh.
        if (isRequest) {
            // Using a threadpool to process requests so we can shut it down
            // when unload the extension.
            ProcessRequestTask processRequest =
                new ProcessRequestTask(
                    toolFlag, requestResponse, extensionConfig
                );

            requestPool.execute(processRequest);

            // Thread reqThread = new Thread(processRequest);
            // reqThread.start();
            return;
        }

        // Here we have responses.
        log.debug("----------");
        log.debug("Got a response.");
        // Create the metadata, it might not be needed if there's nothing in the
        // response but this is a small overhead for more readable code.
        Metadata metadata = new Metadata();
        try {
            metadata = ReqResp.getMetadata(requestResponse);
        } catch (final NoSuchAlgorithmException e) {
            // This should not happen because we are passing "SHA-1" to the
            // digest manually. If we do not have the algorithm in Burp then
            // we have bigger problems.
            final String errMsg = StringUtils.getStackTrace(e);
            log.alert(errMsg);
            log.error(
                "Error creating metadata, algo name is probably wrong: %s.",
                errMsg
            );
            log.debug("Returning from processHttpMessage because of %s", errMsg);
            return;
        }
        log.debug("Response metadata:\n%s", metadata.toString());

        // Here we have responses.
        final IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());

        String scriptHeader = "false";
        String containsScriptHeader = "false";
        String javascript = "";

        if (Detective.isScript(requestResponse)) {
            log.debug("Detected a script response.");

            if (extensionConfig.highlight) {
                scriptHeader = "true";
                requestResponse.setHighlight("cyan");
            }

            // Get the response body.
            final byte[] bodyBytes = ReqResp.getResponseBody(requestResponse);
            if (bodyBytes.length == 0) {
                log.debug("Empty response, returning from processHttpMessage.");
                return;
            }
            javascript = StringUtils.bytesToString(bodyBytes);
        } else if (Detective.containsScript(requestResponse)) {
            // Not a JavaScript file, but it might contain JavaScript.
            log.debug("Detected a contains-script response.");

            if (extensionConfig.highlight) {
                containsScriptHeader = "true";
                requestResponse.setHighlight("yellow");
            }

            // Extract any JavaScript from the response.
            javascript = Extractor.getJS(requestResponse.getResponse());
        }

        // Don't uncomment this unless you are debugging in Repeater. It will
        // fill the debug log with noise.
        // log.debug("Extracted JavaScript:\n%s", javascript);
        // log.debug("End of extracted JavaScript ----------");

        // Set the debug headers.
        if (extensionConfig.debug) {
            requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Is-Script", scriptHeader);
            requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Contains-Script", containsScriptHeader);
            requestResponse = ReqResp.addHeader(isRequest, requestResponse, "MIMETYPEs",
                String.format("%s -- %s", respInfo.getInferredMimeType(), respInfo.getStatedMimeType()));
        }

        if (StringUtils.isEmpty(javascript)) {
            log.debug("Cound not find any in-line JavaScript, returning.");
            return;
        }

        // Check for jsMaxSize.
        if (javascript.length() >= (extensionConfig.jsMaxSize * 1024)) {
            log.debug("Length of JavaScript: %d > %d threshold, returning.",
                javascript.length(), extensionConfig.jsMaxSize * 1024);
            return;
        }

        try {
            // Spawn a new processResponse task that adds the captured
            // JavaScript to the db.
            final Runnable processResponse = new ProcessResponseTask(
                javascript, metadata
            );

            // TODO submit returns a Future that will be null when task is
            // complete. Can we use it?
            // pool.submit(processResponse);

            responsePool.execute(processResponse);

            // Without threadpools.
            // Thread responseThread = new Thread(processResponse);
            // responseThread.start();

        } catch (final Exception e) {
            log.debug("%s", StringUtils.getStackTrace(e));
        }
    }

    // Returns the default config. Default config is the default values for the
    // Config object as set in Config.java.
    private static Config getDefaultConfig() {
        return new Config();
    }

    // Get saved config.
    private static void loadSavedConfig() {
        // See if the extension config was saved in extension settings. If
        // default config was loaded from the file above, it will be saved.
        final String savedConfig = callbacks.loadExtensionSetting("config");
        String decodedConfig = "";

        if (StringUtils.isEmpty(savedConfig)) {
            // No saved config. Use the default version and prompt the user.
            log.alert("No saved config found, please choose one after the extension has loaded.");
        } else {
            // Base64 decode the config string.
            decodedConfig = StringUtils.base64Decode(savedConfig);
            extensionConfig = Config.configBuilder(decodedConfig);
            StringUtils.print("Config loaded from extension settings.");
            log.debug("Decoded config (if any):\n%s", decodedConfig);
            // log.debug("savedConfig: %s", savedConfig);
        }
    }

    private static void loadDefaultConfigFile(String cfgFileName) {
        // Check if there is a file named extensionConfig.defaultConfigName in
        // the current directory, if so, load it and overwrite the extension.
        try {
            // Get the extension jar path.
            String jarPath = callbacks.getExtensionFilename();
            // Get the parent directory of the jar path.
            String jarDirectory = StringUtils.getParentDirectory(jarPath);

            // Create the full path for the default config file.
            // jarDirectory/Config.defaultConfigName.
            String defaultConfigFullPath = FilenameUtils.concat(jarDirectory, cfgFileName);
            File f = new File(defaultConfigFullPath);

            String cfgFile = FileUtils.readFileToString(f, "UTF-8");
            extensionConfig = Config.loadConfig(cfgFile);
            log.debug("Config loaded from default config file %s", defaultConfigFullPath);
        } catch (FileNotFoundException e) {
            log.debug(
                "Default config file '%s' was not found.",
                Config.defaultConfigName
            );
        } catch (Exception e) {
            // If anything goes wrong here, then something else was wrong other
            // than the file not having the correct content.
            log.debug(
                "Error loading default config file %s: %s",
                Config.defaultConfigName,
                StringUtils.getStackTrace(e)
            );
            log.debug("This is not a show stopper, the extension is will continue loading");
        }
    }

    // Connects to the database (or creates it if it does not exist).
    public static void databaseConnect(String dbPath) {
        // Create the database.
        try {
            db = new Database(dbPath);
            log.debug("Created a connection to the database: %s", dbPath);
        } catch (SQLException | IOException e) {
            log.alert("Error accessing the database: %s", dbPath);
            log.error("Error creating database %s", StringUtils.getStackTrace(e));
        }
    }

    // Invoked when the extension is unloaded.
    @Override
    public void extensionUnloaded() {
        log.debug("Starting to unload the extension");
        unloadExtension();
        // Kill the tread.
        processThread.stop();
        keepThread = false;
        log.debug("Unloaded the extension.");
    }

    // Shutdowns the threadpool and waits for the active threads to finish.
    // Closes the DB connection.
    public static void unloadExtension() {
        // Shutdown the threadpool and wait for termination.
        // https://stackoverflow.com/a/1250655

        if (requestPool != null) {
            // Shutdown requestPool. This should be quick.
            requestPool.shutdown();
            try {
                requestPool.awaitTermination(timeout, TimeUnit.SECONDS);
                log.debug("requestPool terminated.");
            } catch (Exception e) {
                log.error("Could not terminate requestPool: %s", StringUtils.getStackTrace(e));
            }
        }

        if (responsePool != null) {
            // Shutdown responsePool. This should be quick.
            responsePool.shutdown();
            try {
                responsePool.awaitTermination(timeout, TimeUnit.SECONDS);
                log.debug("responsePool terminated.");
            } catch (Exception e) {
                log.error("Could not terminate responsePool: %s", StringUtils.getStackTrace(e));
            }
        }
        
        if (pool != null) {
            pool.shutdown();
            try {
                pool.awaitTermination(timeout, TimeUnit.SECONDS);
                log.debug("All threads are terminated.");
            } catch (InterruptedException  e) {
                log.error("Could not terminate all threads: %s", StringUtils.getStackTrace(e));
            }
        }

        try {
            if (db != null) {
                db.close();
                log.debug("Closed the database connection");
            }
        } catch (SQLException e) {
            log.error("Error closing the database connection: %s", StringUtils.getStackTrace(e));
        }


    }
}