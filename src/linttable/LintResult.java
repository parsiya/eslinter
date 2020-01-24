package linttable;

import com.google.gson.Gson;

import lint.Metadata;

/**
 * LintRow
 */
// Displayed in the LintTable.
public class LintResult {

    public Metadata metadata;
    public String host;
    public String url;
    public String hash;
    public transient String beautifiedJavaScript; // transient == does not appear in toString()
    public String status;
    public transient String results; // transient
    public int isProcessed;
    public int numResults;
    
    public LintResult() {}

    public LintResult(
            Metadata metadata, String host, String url, String hash,
            String beautifiedJavaScript, String status, String results,
            int isProcessed, int numResults) {
        
        this.metadata = metadata;
        this.host = host;
        this.url = url;
        this.hash = hash;
        this.beautifiedJavaScript = beautifiedJavaScript;
        this.status = status;
        this.results = results;
        this.isProcessed = isProcessed;
        this.numResults = numResults;
    }

    public String toString() {
        return new Gson().toJson(this);
    }
}