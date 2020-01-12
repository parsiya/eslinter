package burp;

import java.awt.Component;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.SwingUtilities;

import gui.BurpTab;
import lint.BeautifyTask;
import lint.Metadata;
import linttable.LintResult;
import utils.BurpLog;
import utils.ReqResp;
import utils.StringUtils;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static Config extensionConfig;
    public static BurpLog log;
    public static BurpTab mainTab;

    private static ExecutorService pool;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks burpCallbacks) {

        callbacks = burpCallbacks;
        helpers = callbacks.getHelpers();
        // Set the extension name.
        callbacks.setExtensionName(Config.extensionName);

        // Create the log object.
        // Create the logger.
        log = new BurpLog(true);

        // Read the config from the extension settings.
        extensionConfig = new Config();
        
        final String savedConfig = callbacks.loadExtensionSetting("config");
        String decodedConfig = "";

        if (StringUtils.isEmpty(savedConfig) || savedConfig == null) {
            // No saved config. Use the default version and prompt the user.
            log.alert("No saved config found, please choose one.");
        } else {
            // Base64 decode the config string.
            decodedConfig = StringUtils.base64Decode(savedConfig);
            extensionConfig = Config.configBuilder(decodedConfig);
            StringUtils.print("Config loaded from extension settings");
        }

        // Set the debug flag from the loaded
        log.setDebugMode(extensionConfig.debug);

        log.debug("Decoded config (if any):\n%s", decodedConfig);
        // log.debug("savedConfig: %s", savedConfig);

        // Configure the beautify executor service.
        pool = Executors.newFixedThreadPool(extensionConfig.numberOfThreads);
        log.debug("Using %d threads.", extensionConfig.numberOfThreads);

        mainTab = new BurpTab();
        log.debug("Created the main tab.");
        callbacks.customizeUiComponent(mainTab.panel);

        // Add the tab to Burp.
        callbacks.addSuiteTab(BurpExtender.this);
        // Register the listener.
        callbacks.registerHttpListener(BurpExtender.this);

        log.debug("Loaded the extension. End of registerExtenderCallbacks");
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

        log.debug("----------");
        String requestOrResponse = (isRequest) ? "request" : "response";
        log.debug("Got a %s.", requestOrResponse);
        // Create the metadata, it might not be needed if there's nothing in the
        // response but this is a small overhead for more readable code.
        Metadata metadata = new Metadata();
        try {
            metadata = ReqResp.getMetadata(requestResponse);
        } catch (final NoSuchAlgorithmException e) {
            // This should not happen because we are passing "MD5" to the
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
        log.debug("Request or response metadata:\n%s", metadata.toString());

        // Check if the request is in scope.
        if (extensionConfig.processInScope) {
            // Get the request URL.
            URL reqURL = ReqResp.getURL(requestResponse);
            if (!callbacks.isInScope(reqURL)) {
                // Request is not in scope, return.
                log.debug("Request is not in scope, returning from processHttpMessage");
                return;
            }
        }

        // Only process if the callbacks.getToolName(toolFlag) is in
        // processTools, otherwise return.
        final String toolName = callbacks.getToolName(toolFlag);
        log.debug("Got a %s from %s.", requestOrResponse,toolName);
        if (!StringUtils.arrayContains(toolName, extensionConfig.processToolList)) {
            log.debug(
                "%s is not in the process-tool-list, return processHttpMessage",
                toolName
            );
            return;
        }

        // Process requests and get their extension.
        // If their extension matches what we want, get the response.
        if (isRequest) {
            // Remove cache headers from the request. We do not want 304s.
            for (final String rhdr : extensionConfig.headersToRemove) {
                requestResponse = ReqResp.removeHeader(isRequest, requestResponse, rhdr);
            }
            log.debug("Removed headers from the request, returning.");
            return;
        }

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

            // Get the request body.
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

            // Extract JavaScript.
            javascript = Extractor.getJS(requestResponse.getResponse());
        }

        // Don't uncomment this unless you are debugging in Repeater. It will
        // mess up your logs.
        // log.debug("Extracted JavaScript:\n%s", javascript);
        // log.debug("End of extracted JavaScript --------------------");

        // Set the debug headers.
        if (extensionConfig.debug) {
            requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Is-Script", scriptHeader);
            requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Contains-Script", containsScriptHeader);
            requestResponse = ReqResp.addHeader(isRequest, requestResponse, "MIMETYPEs",
                String.format("%s -- %s", respInfo.getInferredMimeType(), respInfo.getStatedMimeType()));
        }

        if (StringUtils.isEmpty(javascript)) {
            log.debug("Response did not have any in-line JavaScript, returning.");
            return;
        }

        // Check for jsMaxSize.
        if (javascript.length() >= (extensionConfig.jsMaxSize * 1024)) {
            log.debug("Length of JavaScript: %d > %d threshold, returning.",
                javascript.length(), extensionConfig.jsMaxSize * 1024);
            return;
        }

        try {
            // Spawn a new BeautifyTask to beautify and store the data.
            final Runnable beautifyTask = new BeautifyTask(
                javascript, metadata, extensionConfig.storagePath
            );

            // Fingers crossed this will work.
            // TODO This presents a Future that will be null when task is
            // complete. Can we use it?
            pool.submit(beautifyTask);
        } catch (final Exception e) {
            log.debug(StringUtils.getStackTrace(e));
            return;
        }
    }
}