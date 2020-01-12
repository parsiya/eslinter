package lint;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import burp.Config;
import utils.StringUtils;

/**
 * Metadata stores the metadata for each JS file.
 */
public class Metadata {
    private String url;
    private String referer;
    private String hash;
    private String id;

    public Metadata() {}

    public Metadata(String u, String ref, String hsh) {
        url = u;
        referer = ref;
        hash = hsh;
        id = calculateID(url, hash);
    }

    // Identifier should be unique if the URL and hash of body match.
    // Identifier is the hash of the URL||Hash.
    private static String calculateID(String u, String h) {
        byte[] json = StringUtils.stringToBytes(u.concat(h));
        byte[] hashBytes;
        try {
            hashBytes = MessageDigest.getInstance("SHA-1").digest(json);
        } catch (NoSuchAlgorithmException e) {
            // This should not happen because Burp has SHA-1.
            return "";
        }
        return StringUtils.encodeHexString(hashBytes);
    }

    public static Metadata fromString(String jsonString) {
        return new Gson().fromJson(jsonString, Metadata.class);
    }

    public String getURL() {
        return url;
    }

    public void setURL(String u) {
        url = u;
    }

    public String getReferer() {
        return referer;
    }

    public void setReferer(String r) {
        referer = r;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String h) {
        hash = h;
    }

    // Returns the metadata object as a json string.
    public String toString() {
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(this);
    }

    // toString() but wrapped in /* */
    public String toCommentString() {
        return "/*\n" + toString() + "\n*/\n\n";
    }

    // Returns the filename calculated from the metadata object minus the
    // extension.

    // Filename will be
    // "filename_from_URL[minus extension and limited to 50 chars]-[hash]".
    public String getFileName() throws MalformedURLException {
        
        String jsFileName = "";

        jsFileName = StringUtils.getURLBaseName(getURL());
        // Limit the file name to Config.urlFileNameLimit.
        if (jsFileName.length() > Config.urlFileNameLimit) {
            jsFileName = jsFileName.substring(0, Config.urlFileNameLimit);
        }
        // Replace illegal characters in the filename.
        // https://stackoverflow.com/a/15075907
        jsFileName = jsFileName.replaceAll("[^a-zA-Z0-9\\.\\-]", "_");
        if (!StringUtils.isEmpty(jsFileName)) {
            // If the URL does not end in a file jsFileName will be empty.
            // If it's not empty, we add the "-" to it.
            jsFileName = jsFileName.concat("-");
        }
        // If jsFileName was empty do nothing.
        // Attach the hash and the extension.
        jsFileName = jsFileName.concat(getHash());
        return jsFileName;
    }

    public String getHost() throws MalformedURLException {
        return new URL(getURL()).getHost();
    }


    // public void fromString(String jsonString) {
    //     Metadata tmpMeta = new Gson().fromJson(jsonString, Metadata.class);
    //     url = tmpMeta.url;
    //     referer = tmpMeta.referer;
    //     hash = tmpMeta.hash;
    // }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}