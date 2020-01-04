package burp;

import utils.ReqResp;

import java.net.URL;
import java.util.ArrayList;
import static burp.BurpExtender.extensionConfig;


/**
 * Detective contains the JavaScript detection functions.
 */
public class Detective {

    private static final String EMPTY_STRING = "";
    private static final String JAVASCRIPT_MIMETYPE = "text/javascript";

    public static boolean isScript(IHttpRequestResponse requestResponse) {

        // 1. Check the requests' extension.
        if (isJSURL(requestResponse)) {
            return true;
        }

        // 2. Check the MIMEType
        String mType = getMIMEType(requestResponse);
        if ((isJSMimeType(mType)) && (mType != EMPTY_STRING)){
            return true;
        }
        return false;
    }
    
    public static String getMIMEType(IHttpRequestResponse requestResponse) {
        // 0. Process the response.
        IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse());
        
        // 1. Try to get the MIME type from the response using Burp.
        String mimeType = respInfo.getStatedMimeType();
        if (mimeType != EMPTY_STRING) return mimeType;
        mimeType = respInfo.getInferredMimeType();
        if (mimeType != EMPTY_STRING) return mimeType;
        
        // I do not think we can do better at Burp but that is not tested yet.
        // 2. Get the "Content-Type" header of the response.
        ArrayList<String> contentTypes = ReqResp.getHeader("Content-Type", false, requestResponse);
        if (contentTypes == null) return EMPTY_STRING;
        for (String cType : contentTypes) {
            // if (cType == null) continue;
            // Check if cType is in Config.JSMIMETypes.
            if (isJSMimeType(cType)) {
                return JAVASCRIPT_MIMETYPE;
            }
        }

        // 3. guessContentTypeFromName does not detect *.js files.

        // TODO Anything else?
        return EMPTY_STRING;
    }

    public static boolean containsScript(IHttpRequestResponse requestResponse) {
        // Get the Content-Type and check it against ContainsScriptTypes.
        // If so, get everything between "<script.*>(.*)</script>".
        ArrayList<String> responseContentType =
            ReqResp.getHeader("Content-Type", false, requestResponse);
        
        if (responseContentType == null) return false;
        for (String cType : responseContentType) {
            if (cType == null) continue;
            if(isContainsScriptType(cType)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isContainsScriptType(String cType) {
        if (cType == null) {
            return false;
        }
        for (String ct : extensionConfig.ContainsScriptTypes) {
            if (cType.contains(ct)) return true;
        }
        return false;
    }

    private static boolean isJSMimeType(String mType) {
        // return Arrays.asList(Config.JSTypes).contains(mType.toLowerCase());
        if (mType == null) {
            return false;
        }
        // Loop through all JSTypes and see if they occur in any of the headers.
        // This is better because the header usually contains the content-type
        // and stuff like charset.
        for (String jt : extensionConfig.JSTypes) {
            if (mType.contains(jt)) return true;
        }
        return false;
    }

    private static boolean isJSURL(IHttpRequestResponse requestResponse) {
        // Get the extension URL.
        String ext = ReqResp.getRequestExtension(requestResponse);
        // Return true if it's one of the extensions we are looking for.
        if (ext == null) return false;
        for (String extension : extensionConfig.FileExtensions) {
            if (ext.equalsIgnoreCase(extension)) {
                return true;
            }
        }
        return false;
    }

    public static URL getRequestURL(IHttpRequestResponse requestResponse) {
        IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
        return reqInfo.getUrl();
    }

}