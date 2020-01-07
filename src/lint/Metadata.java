package lint;

import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import utils.StringUtils;

/**
 * Metadata stores the metadata for each JS file.
 */
public class Metadata {
    private String url;
    private String referer;
    private String hash;
    // private boolean beautified = false;
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
    public static String calculateID(String u, String h) {
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

    public String getUrl() {
        return url;
    }

    public void setUrl(String u) {
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

    public String toString() {
        return new GsonBuilder().setPrettyPrinting().create().toJson(this);
    }

    // toString() but wrapped in /* */
    public String toCommentString() {
        // StringWriter sw = new StringWriter();
        // sw.write("/*\n");
        // sw.write(toString());
        // sw.write("\n*/\n\n");
        // return sw.toString();
        return "/*\n" + toString() + "\n*/\n\n";
    }

    // public void fromString(String jsonString) {
    //     Metadata tmpMeta = new Gson().fromJson(jsonString, Metadata.class);
    //     url = tmpMeta.url;
    //     referer = tmpMeta.referer;
    //     hash = tmpMeta.hash;
    // }

    // public boolean isBeautified() {
    //     return beautified;
    // }

    // public void setBeautified(boolean done) {
    //     this.beautified = done;
    // }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}