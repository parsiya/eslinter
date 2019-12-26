package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.JPanel;

import lint.Beautify;
import lint.BeautifyNotFound;
import lint.BeautifyTask;
import lint.Metadata;
import utils.ReqResp;
import utils.StringUtils;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    // private static String EMPTY_STRING = "";
    private static Beautify beautifier = null;
    private static ExecutorService pool;

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

        // Here we have responses.
        IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());
        String scriptHeader = "false";

        if (Detective.isScript(requestResponse)) {
            return;
            // scriptHeader = "true";
            // requestResponse.setHighlight("cyan");
            // // We need to get this file and store it.

            // // Create the MetaData.
            // Metadata metadata = new Metadata();
            // try {
            //     metadata = ReqResp.getMetadata(requestResponse);
            // } catch (NoSuchAlgorithmException e) {
            //     // This should not happen because we are passing "MD5" to the
            //     // digest manually. If we do not have the algorithm in Burp then
            //     // we have bigger problems.
            //     e.printStackTrace();
            //     return;
            // }

            // // Get the request body.
            // byte[] bodyBytes = ReqResp.getResponseBody(requestResponse);
            // if (bodyBytes.length == 0) return;

            // // TODO Spawn all of this in a new thread.

            // // String metadataString = metadata.toString();
            // // String filePath = "C:\\Users\\IEUser\\Desktop\\eslint\\".concat(metadata.getHash().concat(".js"));
            //  try {
            //     // PrintWriter pOut = new PrintWriter(filePath);
            //     // pOut.write("/*\n");
            //     // pOut.write(metadataString);
            //     // pOut.write("\n*/\n\n");
            //     // pOut.write(helpers.bytesToString(bodyBytes));
            //     // pOut.close();
            //     // callbacks.printOutput("whatever");
            //     // Now beautify the file.
            //     // StringWriter sw = new StringWriter();
            //     // sw.write("/*\n");
            //     // sw.write(metadataString);
            //     // sw.write("\n*/\n\n");
            //     // sw.write(helpers.bytesToString(bodyBytes));
            //     // sw.close();

            //     // JSBeautify.beautifyFile(filePath, filePath);
            //     // String beautifiedStr = beautifier.beautify(sw.toString());
            //     // if (StringUtils.isEmpty(beautifiedStr)) {
            //     //     callbacks.printError("beautify(" + metadata.getUrl() + ") was empty.");
            //     //     return;
            //     // }
                
            //     // File outFile = new File(filePath);
            //     // FileUtils.writeStringToFile(outFile, beautifiedStr, "UTF-8");
                
            //     // String output = Exec.execute("C:\\Users\\IEUser\\Desktop\\eslint", "js-beautify.exe", "-f", filePath, "-r");
            //     // callbacks.printOutput(output);

            //     // Spawn a new BeautifyTask to beautify and store the thing.
            //     Runnable beautifyTask = new BeautifyTask(
            //         beautifier, StringUtils.bytesToString(bodyBytes), metadata,
            //         Config.StoragePath);
                
            //     // Fingers crossed this will work.
            //     // TODO This presents a Future that will be null when task is
            //     // complete. Can we use it?
            //     pool.submit(beautifyTask);


            // } catch (Exception e) {
            //     // TODO Auto-generated catch block
            //     StringUtils.printStackTrace(e);
            // }

        }
        requestResponse = ReqResp.addHeader(isRequest, requestResponse, "Is-Script", scriptHeader);

        String containsScriptHeader = "false";
        // Not a JavaScript file, but it might contain it.
        if (Detective.containsScript(requestResponse)) {
            containsScriptHeader = "true";
            requestResponse.setHighlight("red");
            // TODO Extract and beautify stuff here too.
            // Do not forget to add metadata.
            // callbacks.printOutput("-------------------------");
            // callbacks.printOutput(String.format("Extracted JS from: %s", requestResponse.getHttpService().toString()));
            // callbacks.printOutput(Extractor.getJS(requestResponse.getResponse()));
            // callbacks.printOutput("-------------------------");

            String extractedJS = Extractor.getJS(requestResponse.getResponse());
            if (StringUtils.isEmpty(extractedJS)) return;

            // Create the MetaData.
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

            try {
                // Spawn a new BeautifyTask to beautify and store the thing.
                Runnable beautifyTask = new BeautifyTask(
                    beautifier, extractedJS, metadata, Config.StoragePath);
                
                // Fingers crossed this will work.
                // TODO This presents a Future that will be null when task is
                // complete. Can we use it?
                pool.submit(beautifyTask);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                StringUtils.printStackTrace(e);
            }    
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