package database;

import linttable.LintResult;

/**
 * SelectResult contains a LintResult with its associated rowid.
 */
public class SelectResult {

    public long rowid;
    public LintResult lr;

    public SelectResult(long id, LintResult lintResult) {

        rowid = id;
        lr = lintResult;
    }
}