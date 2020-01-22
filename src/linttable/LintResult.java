package linttable;

import com.google.gson.Gson;

import lint.Metadata;

/**
 * LintRow
 */
// Displayed in the LintTable.
public class LintResult {

    public String host;
    public String url;
    public String status;
    public int numResults;
    public transient String results; // We do not want this to end up in toString().
    public transient String beautifiedJS;
    public Metadata metadata;

    public LintResult() {}

    public LintResult(
        String host, String url, String status, int numResults, String results,
        String beautifiedJS, Metadata metadata) {

        this.host = host;
        this.url = url;
        this.status = status;
        this.numResults = numResults;
        this.results = results;
        this.beautifiedJS = beautifiedJS;
        this.metadata = metadata;
    }

    public String toString() {
        return new Gson().toJson(this);
    }


}