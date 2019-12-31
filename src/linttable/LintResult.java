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

    public LintResult() {}

    public LintResult(String host, String url, String status, int numResults) {
        this.host = host;
        this.url = url;
        this.status = status;
        this.numResults = numResults;
    }

    public String toString() {
        return new Gson().toJson(this);
    }


}