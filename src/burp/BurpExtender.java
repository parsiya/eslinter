package burp;

import java.awt.Component;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.SwingUtilities;

import gui.BurpTab;
import lint.Beautify;
import lint.BeautifyNotFound;
import lint.BeautifyTask;
import lint.Metadata;
import linttable.LintResult;
import utils.ReqResp;
import utils.StringUtils;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    // private static String EMPTY_STRING = "";
    private static Beautify beautifier = null;
    private static ExecutorService pool;
    private BurpTab mainTab;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks burpCallbacks) {

        callbacks = burpCallbacks;
        helpers = callbacks.getHelpers();
        // Read the config file.
        // set our extension name
        callbacks.setExtensionName(Config.ExtensionName);

        // Create the Beautify class.
        try {
            beautifier = new Beautify();
        } catch (BeautifyNotFound e) {
            // If beautify.js was not found, issue a warning.
            StringUtils.printStackTrace(e);
            callbacks.issueAlert(StringUtils.getStackTrace(e));
            return;
        }

        // Configure the beautify executor service.
        pool = Executors.newFixedThreadPool(Config.NumberOfThreads);

        mainTab = new BurpTab();
        callbacks.customizeUiComponent(mainTab.panel);

        // Add the tab to Burp.
        callbacks.addSuiteTab(BurpExtender.this);
        // Register the listener.
        callbacks.registerHttpListener(BurpExtender.this);
    }

    @Override
    public String getTabCaption() {
        return Config.TabName;
    }

    @Override
    public Component getUiComponent() {
        // Return the tab here.
        return mainTab.panel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse requestResponse) {

        if (requestResponse == null) return;

        // Process requests and get their extension.
        // If their extension matches what we want, get the response.
        if (isRequest) {
            // Remove cache headers from the request. We do not want 304s.
            for (String rhdr : Config.RemovedHeaders) {
                requestResponse = ReqResp.removeHeader(isRequest, requestResponse, rhdr);
            }
            return;
        }

        // Here we have responses.
        IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());

        // Create the metadata, it might not be needed if there's nothing in the
        // response but this is a small overhead for more readable code.

        Metadata metadata = new Metadata();
        try {
            metadata = ReqResp.getMetadata(requestResponse);
        } catch (NoSuchAlgorithmException e) {
            // This should not happen because we are passing "MD5" to the
            // digest manually. If we do not have the algorithm in Burp then
            // we have bigger problems.
            e.printStackTrace();
            return;
        }

        String scriptHeader = "false";
        String containsScriptHeader = "false";
        String javascript = "";

        if (Detective.isScript(requestResponse)) {
            scriptHeader = "true";
            requestResponse.setHighlight("cyan");
            // Get the request body.
            byte[] bodyBytes = ReqResp.getResponseBody(requestResponse);
            if (bodyBytes.length == 0) return;

            javascript = StringUtils.bytesToString(bodyBytes);
        } else if (Detective.containsScript(requestResponse)) {
            // Not a JavaScript file, but it might contain JavaScript.
            containsScriptHeader = "true";
            requestResponse.setHighlight("red");
            // Extract JavaScript.
            javascript = Extractor.getJS(requestResponse.getResponse());
        }

        // Set the debug headers.
        // TODO Only do this in debug mode?
        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Is-Script", scriptHeader);
        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Contains-Script", containsScriptHeader);
        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "MIMETYPEs",
            String.format("%s -- %s", respInfo.getInferredMimeType(), respInfo.getStatedMimeType()));

        if (StringUtils.isEmpty(javascript)) {
            return;
        }

        // try {
        //     // Spawn a new BeautifyTask to beautify and store the data.
        //     Runnable beautifyTask = new BeautifyTask(
        //         beautifier, javascript, metadata, Config.StoragePath);
            
        //     // Fingers crossed this will work.
        //     // TODO This presents a Future that will be null when task is
        //     // complete. Can we use it?
        //     pool.submit(beautifyTask);
        // } catch (Exception e) {
        //     // TODO Auto-generated catch block
        //     StringUtils.printStackTrace(e);
        //     return;
        // }

        // Create the LintResult and add to the table.
        LintResult lr = new LintResult(
            ReqResp.getHost(requestResponse),
            ReqResp.getURL(requestResponse).toString(), "Added", 0
        );

        SwingUtilities.invokeLater (new Runnable () {
            @Override
            public void run () {
                mainTab.lintTable.add(lr);
            }
        });
    }
}