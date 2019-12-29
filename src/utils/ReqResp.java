package utils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import lint.Metadata;
import utils.StringUtils;

import static burp.BurpExtender.helpers;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;


/**
 * ReqResp
 */
public class ReqResp {

    public static byte[] getRequestBody(IHttpRequestResponse requestResponse) {
        byte[] requestBytes = requestResponse.getRequest();
        IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
        int bodyOffset = reqInfo.getBodyOffset();
        int requestSize = requestBytes.length;
        int bodySize = requestSize - bodyOffset;
        byte[] bodyBytes = new byte[bodySize];
        System.arraycopy(requestBytes, bodyOffset, bodyBytes, 0, bodySize);
        return bodyBytes;
    }

    public static byte[] getResponseBody(IHttpRequestResponse requestResponse) {
        byte[] responseBytes = requestResponse.getResponse();
        IResponseInfo respInfo = helpers.analyzeResponse(responseBytes);
        int bodyOffset = respInfo.getBodyOffset();
        int responseSize = responseBytes.length;
        int bodySize = responseSize - bodyOffset;
        byte[] bodyBytes = new byte[bodySize];
        System.arraycopy(responseBytes, bodyOffset, bodyBytes, 0, bodySize);
        return bodyBytes;
    }

    public static byte[] getBody(boolean isRequest,
        IHttpRequestResponse requestResponse) {
        
        if (isRequest) {
            return getRequestBody(requestResponse);
        }
        return getResponseBody(requestResponse); 
    }

    public static IHttpRequestResponse addHeader(boolean isRequest,
        IHttpRequestResponse requestResponse, String header, String value) {
        
        // Add a header to the request or response.
        Header hdr = new Header(isRequest, requestResponse);
        hdr.add(header, value);
        // Get the body.
        byte[] body = getBody(isRequest, requestResponse);
        // Build the HTTP message.
        byte[] modifiedMsg = helpers.buildHttpMessage(hdr.exportToBurp(), body);
        if (isRequest) {
            requestResponse.setRequest(modifiedMsg);
        } else {
            requestResponse.setResponse(modifiedMsg);
        }
        return requestResponse;
    }

    public static IHttpRequestResponse removeHeader(boolean isRequest,
        IHttpRequestResponse requestResponse, String headerName) {
        
        Header hdr = new Header(isRequest, requestResponse);
        hdr.remove(headerName);
        // Get the body.
        byte[] body = getBody(isRequest, requestResponse);
        // Build the HTTP message.
        byte[] modifiedMsg = helpers.buildHttpMessage(hdr.exportToBurp(), body);
        if (isRequest) {
            requestResponse.setRequest(modifiedMsg);
        } else {
            requestResponse.setResponse(modifiedMsg);
        }
        return requestResponse;
    }

    public static ArrayList<String> getHeader(String header, boolean isRequest,
        IHttpRequestResponse requestResponse) {

        Header hdr = new Header(isRequest, requestResponse);
        return hdr.get(header);
    }

    // Returns the java.net.URL for the IHttpRequestResponse's request.
    public static java.net.URL getURL(IHttpRequestResponse requestResponse) {
        IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
        return reqInfo.getUrl();
    }

    // Creates and returns the metadat for the IHttpRequestResponse.
    public static Metadata getMetadata(IHttpRequestResponse requestResponse) throws NoSuchAlgorithmException {

        String url = ReqResp.getURL(requestResponse).toString();
        // If there is no Referer header, getHeader will be null and we cannot
        // call .get(0) on it.
        ArrayList<String> refererHeaders = ReqResp.getHeader("Referer", true, requestResponse);
        String referer = "";
        if (refererHeaders != null) {
            referer = refererHeaders.get(0);
        }
        byte[] bodyBytes = ReqResp.getResponseBody(requestResponse);
        byte[] hashBytes = MessageDigest.getInstance("MD5").digest(bodyBytes);
        String hashString = StringUtils.encodeHexString(hashBytes);
        return new Metadata(url, referer, hashString);
    }

}