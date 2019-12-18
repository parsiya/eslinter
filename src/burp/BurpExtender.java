package burp;

import java.awt.Component;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.awt.BorderLayout;
import javax.swing.JPanel;

import lint.Metadata;
import utils.ReqResp;
import utils.StringUtils;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

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
        // TODO Return the tab here.
        JPanel panel = new JPanel(new BorderLayout());
        return panel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse requestResponse) {

        // Process requests and get their extension.
        // If their extension matches what we want, get the response.
        if (isRequest) {
            // Remove cache headers from the request. We do not want 304s.
            for (String rhdr : Config.RemovedHeaders) {
                requestResponse = ReqResp.removeHeader(isRequest, requestResponse, rhdr);
            }
            return;
        }

        // Remember to do stuff inside swing dispatching threads?

        // Here we have responses.
        IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());
        String scriptHeader = "false";
        if (Detective.isScript(requestResponse)) {
            scriptHeader = "true";
            requestResponse.setHighlight("cyan");
            // We need to get this file and store it.

            // Create the MetaData.
            Metadata metadata = new Metadata();
            try {
                metadata = ReqResp.getMetadata(requestResponse);
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block

                // This should not happen because we are passing "MD5" to the
                // digest manually. If we do not have the algorithm in Burp then
                // we have bigger problems.
                e.printStackTrace();
            }

            // Get the request body.
            byte[] bodyBytes = ReqResp.getResponseBody(requestResponse);

            String metadataString = metadata.toString();
            String filePath = "C:\\Users\\IEUser\\Desktop\\eslint\\".concat(metadata.getHash().concat(".js"));
             try {
                PrintWriter pOut = new PrintWriter(filePath);
                pOut.write("\n/*\n");
                pOut.write(metadataString);
                pOut.write("\n*/\n\n");
                pOut.write(helpers.bytesToString(bodyBytes));
                pOut.close();
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }
        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Is-Script", scriptHeader);
        

        String containsScriptHeader = "false";
        if (Detective.containsScript(requestResponse)) {
            containsScriptHeader = "true";
            requestResponse.setHighlight("red");
            callbacks.printOutput("-------------------------");
            callbacks.printOutput(String.format("Extracted JS from: %s", requestResponse.getHttpService().toString()));
            callbacks.printOutput(Extractor.getJS(requestResponse.getResponse()));
            callbacks.printOutput("-------------------------");
        }
        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Contains-Script", containsScriptHeader);

        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "MIMETYPEs",
            String.format("%s -- %s", respInfo.getInferredMimeType(), respInfo.getStatedMimeType()));

        // 1. TODO Check if the URL has already been processed.
        // URL#sameFile(URL other) will be useful here.



        // 3. TODO Get the request extension.


        // Compare it against our internal list.
        // 3. TODO Add this list to the extension's config.

        // Process HTTP responses here and extract scripts from them.
        

        // TODO #1 Option to only run the linter on requests in certain tools
        // (e.g., proxy or repeater). The toolFlag variable should be used.

        // Process the response and get the scripts.


    }
}