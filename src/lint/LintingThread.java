package lint;

import static burp.BurpExtender.db;
import static burp.BurpExtender.log;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import burp.Config;
import database.SelectResult;
import utils.PausableExecutor;
import utils.StringUtils;

/**
 * ProcessLintQueue
 */
public class LintingThread implements Runnable {

    private final PausableExecutor pool;
    private final Config extensionConfig;
    private long lastRowID = 0;
    private volatile boolean running;

    public LintingThread(Config extensionConfig, PausableExecutor pool)  {

        this.extensionConfig = extensionConfig;
        this.pool = pool;
        this.running = true;
    }

    // 1. Read every row where (rowid > lastRowID AND is_processed != 1)
    // 2. Add each row to the threadpool and update lastRowID if it's larger
    //    than the current one.
    // 3. Update lastRowID with the largest row. Last record will have the
    //    largest row.
    // 4. Sleep for X seconds.
    // 5. Go to 1.
    public void process() throws IOException, SQLException, InterruptedException {

        while(running) {
            if (db != null) {
                // 1. Read every row where (rowid > lastRowID AND is_processed != 1)
                final ArrayList<SelectResult> results = db.getNewRows(lastRowID);
                log.debug("Inside ProcessLintQueue - Reading the results.");

                // 2. Add each row to the threadpool.
                for (SelectResult res : results) {
            
                    log.debug("Inside ProcessLintQueue - res.rowid: %d.", res.rowid);
                    // Check if res.lr.hash exists in the threadpool.
                    // Add each res to the threadpool.
                    pool.execute(new LintTask(extensionConfig, res.lr));
                    // 3. Update lastRowID.
                    // Update the lastRowID because things might go bad in the middle.
                    if (res.rowid > lastRowID) lastRowID = res.rowid;
                }
                log.debug("Inside ProcessLintQueue - Finished iterating through the results.");
                log.debug("Inside ProcessLintQueue - lastrowid %d.", lastRowID);

                // We could also update lastRowID here with the rowID of the last record
                // in results. Foreach does not change the order.

                log.debug("Inside ProcessLintQueue - Sleeping for %d seconds.", extensionConfig.lintTaskDelay);
                // 4. Sleep for X seconds.
                Thread.sleep(extensionConfig.lintTaskDelay * 1000);

                /// 5. Go to 1.
            }
        }

        log.debug("Inside ProcessLintQueue - Done with the ProcessLintQueue thread.");
        pool.pause();
        // Let's see if closing the database here fixes issue #30.
        db.close();
        log.debug("Inside ProcessLintQueue - Finished after pool is paused.");
    }

    @Override
    public void run() {
        try {
            process();
        } catch (Exception e) {
            log.error("Inside ProcessLintQueue - %s", StringUtils.getStackTrace(e));
        }
    }

    // Stop the thread.
    public void stop() {
        running = false;
    }

    // Wrap it in a thread.
    public void start() {
        new Thread(this).start();
    }
    
}