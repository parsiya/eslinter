package lint;

import static burp.BurpExtender.db;
import static burp.BurpExtender.log;
import java.io.IOException;
import java.sql.SQLException;
import burp.Config;
import linttable.LintResult;
import utils.StringUtils;

/**
 * LintTask
 */
public class LintTask implements Runnable {

    // private Metadata metadata;
    private Config extensionConfig;
    private LintResult lr;
    private String status = "";

    public LintTask(Config extensionConfig, LintResult lr) {
        this.extensionConfig = extensionConfig;
        this.lr = lr;
    }

    @Override
    public void run() {

        LintResult linted = null;

        try {
            // First we need to beautify.
            Beautify be = new Beautify(lr.beautifiedJavaScript, lr.metadata, extensionConfig.storagePath,
                    extensionConfig.jsBeautifyCommandPath);

            String beautifiedJS = be.execute();

            // Next we need to lint it.
            Lint lint = new Lint(lr.metadata, beautifiedJS, extensionConfig);

            linted = lint.execute();

        } catch (CustomException e) {
            log.error("Inside LintTask for %s - %s", e.getMessage(), lr.metadata.toUglyString());
            status = e.getMessage();
        } catch (IOException e) {
            log.error("Inside LintTask for %s - %s", StringUtils.getStackTrace(e), lr.metadata.toUglyString());
            status += e.getMessage();
        } catch (Exception e) { // TODO Is this needed?
            log.error("Inside LintTask for %s - %s", StringUtils.getStackTrace(e), lr.metadata.toUglyString());
            status += e.getMessage();
        } finally {

            // If linted != null, there was an error.
            // We update the status and store the original LintResult.

            // This means that if beautify was executed w/o errors and lint
            // failed, we are throwing away the beautify results away.
            LintResult updatedRecord;

            if (linted != null) {
                updatedRecord = linted;
            } else {
                updatedRecord = lr;
                updatedRecord.status = status;
            }

            try {
                int up = db.updateRow(updatedRecord);
                log.debug("db.updateRow: %d", up);
            } catch (IOException | SQLException e) {
                log.error("Inside LintTask for %s - %s", StringUtils.getStackTrace(e), lr.metadata.toUglyString());
            }
        }
    }

}