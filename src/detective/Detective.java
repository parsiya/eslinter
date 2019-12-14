package detective;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.Config;
import static burp.BurpExtender.helpers;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Detective contains the JavaScript detection functions.
 */
public class Detective {

    private static final String EMPTY_STRING = "";

    public boolean isScript(IHttpRequestResponse requestResponse) {

        // 1. Check the requests' extension.
        boolean jsURL = isJSURL(requestResponse);
        if (jsURL) {
            return true;
        }

        // 2. Check the MIMEType
        String mType = getMIMEType(requestResponse);
        if (isJSMimeType(mType)){
            return true;
        }

        return false;
    }
    
    public static String getMIMEType(IHttpRequestResponse requestResponse) {
        // 0. Process the response.
        IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());
        
        // 1. Try to get the MIME type from the response using Burp.
        String mimeType = respInfo.getStatedMimeType();
        if (mimeType != EMPTY_STRING) return mimeType;
        mimeType = respInfo.getInferredMimeType();
        if (mimeType != EMPTY_STRING) return mimeType;
        
        // I do not think we can do better at Burp but that is not tested yet.
        // 2. Get the "Content-Type" header of the response.
        Map<String, ArrayList<String>> headers = getHeaders(false, requestResponse);
        ArrayList<String> contentTypes = headers.get("content-type");
        for (String cType : contentTypes) {
            // Check if cnt is in Config.JSMIMETypes.
            if (isJSMimeType(cType)) {
                return "text/javascripot";
            }
        }

        // TODO Anything else?
        // 3.

        return EMPTY_STRING;
    }

    private static boolean isJSMimeType(String mType) {
        return Arrays.asList(Config.JSMIMETypes).contains(mType.toLowerCase());
    }

    private static boolean isJSURL(IHttpRequestResponse requestResponse) {
        // Get the extension URL.
        String ext = getRequestExtension(requestResponse);
        for (String extension : Config.FileExtensions) {
            if (ext.equalsIgnoreCase(extension)) {
                return true;
            }
        }
        return false;
    }

    private static String getRequestExtension(IHttpRequestResponse requestResponse) {
        // Get the request URL.
        // TODO Remove this if it's not needed later.
        // URL requestURL = getRequestURL(requestResponse);
        return FilenameUtils.getExtension(getRequestURL(requestResponse).getPath());
        /**
         * URL u = new
         * URL("https://example.net/path/to/whatever.js?param1=val1&param2=val2");
         * System.out.printf("getFile(): %s\n", u.getFile());
         * System.out.printf("getPath(): %s\n", u.getPath());
         * 
         * URL.getPath() returns the path including the initial /. getPath():
         * /path/to/whatever.js URL.getFile() return getPath along with GET query
         * string. getFile(): /path/to/whatever.js?param1=val1&param2=val2
         */
    }

    private static URL getRequestURL(IHttpRequestResponse requestResponse) {
        IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
        return reqInfo.getUrl();
    }

    private static Map<String, ArrayList<String>> getHeaders(boolean isRequest,
        IHttpRequestResponse requestResponse) {
        
        Map<String,ArrayList<String>> headers = new HashMap<String,ArrayList<String>>();
        
        // Get the headers from Burp.
        List<String> burpHeaders = null;
        if (isRequest) {
            burpHeaders = helpers.analyzeRequest(requestResponse).getHeaders();
        } else {
            byte[] respBytes = requestResponse.getResponse();
            burpHeaders = helpers.analyzeResponse(respBytes).getHeaders();
        }
        
        // If Burp does not have any headers then return null.
        if (burpHeaders == null) {
            return null;
        }

        // First line is "GET /whatever HTTP/1.1".
        for (String header : burpHeaders) {
            // Split only once.
            String[] halves = header.split(":", 2);
            // Remove whitespace from both parts.
            // Keys are also lowercase.
            halves[0] = halves[0].trim().toLowerCase();
            halves[1] = halves[1].trim();
            
            // Check if the header already exists in the map.
            ArrayList<String> vals = null;
            if (headers.get(halves[0]) == null) {
                // If not, create the ArrayList.
                vals = new ArrayList<String>();
            } else {
                // Get the existing ArrayList.
                vals = headers.get(halves[0]);
            }
            vals.add(halves[1]);
            headers.put(halves[0], vals);
        }
        return headers;
    }


}