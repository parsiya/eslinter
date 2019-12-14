package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import javax.swing.JPanel;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    private static final String EMPTY_STRING = "";

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
        
        boolean getResponse = false;

        // Process requests and get their extension.
        // If their extension matches what we want, get the response.
        if (isRequest) {

            // TODO Remove cache headers from the request. We do not want 304s.
            // 
            return;
        }

        // Now we have responses.
        


        // Grab everything between "<script(.*)</script>" honestly!!!1!!!
        
        // 2. Get the "Content-Type" header and check it against JSMIMETypes.
        


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