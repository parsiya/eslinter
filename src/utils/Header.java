package utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import burp.IHttpRequestResponse;
import static burp.BurpExtender.helpers;

/**
 * Header class.
 */
public class Header {

    private Map<String, ArrayList<String>> hdr;
    private String first;

    public Header() {
        // Using a TreeMap like this will make the keys be case-insensitive.
        // https://stackoverflow.com/a/22336599
        hdr = new TreeMap<String,ArrayList<String>>(String.CASE_INSENSITIVE_ORDER);
        first = "";
    }

    public Header(boolean isRequest, IHttpRequestResponse requestResponse) {
        hdr = getBurpHeaders(isRequest, requestResponse);
        List<String> tmpHeaders = importFromBurp(isRequest, requestResponse);
        if (tmpHeaders != null) {
            first = tmpHeaders.get(0);
        } else {
            first = null;
        }
    }

    public void add(String header, String value) {
        ArrayList<String> vals;
        if(hdr.get(header) == null) {
            // If not, create the ArrayList.
            vals = new ArrayList<String>();
        } else {
            // Get the existing ArrayList.
            vals = hdr.get(header);
        }
        vals.add(value);
        hdr.put(header, vals);
    }

    public ArrayList<String> get(String header) {
        return hdr.get(header);
    }

    public void overwrite(String header, String value) {
        ArrayList<String> vals = new ArrayList<String>();
        vals.add(value);
        hdr.put(header, vals);
    }

    public void remove(String header) {
        hdr.remove(header);
    }

    public static List<String> importFromBurp(boolean isRequest, IHttpRequestResponse requestResponse) {
        // Get the headers from Burp.
        List<String> burpHeaders = null;
        if (isRequest) {
            burpHeaders = helpers.analyzeRequest(requestResponse).getHeaders();
        } else {
            byte[] respBytes = requestResponse.getResponse();
            burpHeaders = helpers.analyzeResponse(respBytes).getHeaders();
        }
        return burpHeaders;
    }

    public List<String> exportToBurp() {
        List<String> headers = new ArrayList<String>();
        // Add the first line.
        headers.add(first);
        // Add the rest of the headers.
        for (Map.Entry<String, ArrayList<String>> h : hdr.entrySet()) {
            // If a header has multiple values, repeat the header.
            for (String val : h.getValue()) {
                headers.add(String.format("%s: %s", h.getKey(), val));
            }
        }
        return headers;
    }

    // Static methods

    public static Map<String, ArrayList<String>> getBurpHeaders(boolean isRequest,
        IHttpRequestResponse requestResponse) {
        
        Map<String,ArrayList<String>> headers = new TreeMap<String,ArrayList<String>>(String.CASE_INSENSITIVE_ORDER);
        
        // Get the headers from Burp.
        List<String> burpHeaders = importFromBurp(isRequest, requestResponse);

        // If Burp does not have any headers then return null.
        if (burpHeaders == null) {
            return null;
        }

        // First line is "GET /whatever HTTP/1.1", we will skip it.
        for (String header : burpHeaders.subList(1, burpHeaders.size())) {
            // Split only once.
            String[] halves = header.split(":", 2);
            // Remove whitespace from both parts.
            halves[0] = halves[0].trim();
            halves[1] = halves[1].trim();

            // Check if the header already exists in the map.
            ArrayList<String> vals;
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