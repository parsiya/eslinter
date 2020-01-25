package lint;

import static burp.BurpExtender.db;
import static burp.BurpExtender.keepThread;
import static burp.BurpExtender.log;
import static burp.BurpExtender.mainTab;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.swing.SwingUtilities;

import burp.Config;
import linttable.LintResult;
import utils.StringUtils;

/**
 * UpdateTableTask updates the table with the results from the database.
 */
public class UpdateTableTask implements Runnable {

    private Config extensionConfig;

    // TODO Get this from the extension config.
    private final int timeout = 1;

    public UpdateTableTask(Config extensionConfig) {
        this.extensionConfig = extensionConfig;
    }

    // 1. Read all rows from the database.
    // 2. Delete all rows in the table model.
    // 3. Add all new rows to the JTable.
    public void process() throws IOException, SQLException, InterruptedException {

        while(keepThread) {
            if (db != null) {
                // 1. Read every row from the table eslint in the database.
                final ArrayList<LintResult> results = db.getAllRows();
                log.debug("Inside UpdateTableTask - Reading all rows.");

                // 2. Delete all rows in the table model.
                // 3. Add all rows to the table.
                // populate() does both.
                // Do everything inside the Swing Event Dispatch Thread.
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        if (mainTab != null) {
                            mainTab.lintTable.populate(results);
                        }
                        log.debug("Inside UpdateTableTask - Updated the table from the database.");
                    }
                });

                log.debug("Inside UpdateTableTask - Sleeping for %d seconds.", timeout);
                // 4. Sleep for X seconds.
                Thread.sleep(timeout * 1000);

                /// 5. Go to 1.
            }
        }
        log.debug("Inside UpdateTableTask - Done with the thread.");
    }

    @Override
    public void run() {
        try {
            process();
        } catch (Exception e) {
            log.error("Inside UpdateTableTask - %s.", StringUtils.getStackTrace(e));
        }
    }

    
}