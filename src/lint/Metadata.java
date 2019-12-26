package lint;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Metadata stores the metadata for each JS file.
 */
public class Metadata {
    private String url;
    private String referer;
    private String hash;
    private boolean beautified = false;

    public Metadata() {}

    public Metadata(String u, String ref, String hsh) {
        url = u;
        referer = ref;
        hash = hsh;
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

    // public void fromString(String jsonString) {
    //     Metadata tmpMeta = new Gson().fromJson(jsonString, Metadata.class);
    //     url = tmpMeta.url;
    //     referer = tmpMeta.referer;
    //     hash = tmpMeta.hash;
    // }

    public static Metadata fromString(String jsonString) {
        return new Gson().fromJson(jsonString, Metadata.class);
    }

    public boolean isBeautified() {
        return beautified;
    }

    public void setBeautified(boolean done) {
        this.beautified = done;
    }
}