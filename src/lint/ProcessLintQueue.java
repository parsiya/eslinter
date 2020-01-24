package lint;

import static burp.BurpExtender.db;
import static burp.BurpExtender.keepThread;
import static burp.BurpExtender.log;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import burp.Config;
import database.SelectResult;
import utils.StringUtils;

/**
 * ProcessLintQueue
 */
public class ProcessLintQueue implements Runnable {

    private final ExecutorService pool;
    private final Config extensionConfig;
    private static long lastRowID = 0;

    // TODO Change this in config?
    private final int timeout = 5;

    public ProcessLintQueue(Config extensionConfig, ExecutorService pool)  {

        this.extensionConfig = extensionConfig;
        this.pool = pool;
    }

    // 1. Read every row where (rowid > lastRowID AND is_processed != 1)
    // 2. Add each row to the threadpool and update lastRowID if it's larger
    //    than the current one.
    // 3. Update lastRowID with the largest row. Last record will have the
    //    largest row.
    // 4. Sleep for X seconds.
    // 5. Go to 1.
    public void process() throws IOException, SQLException, InterruptedException {

        while(keepThread) {
            if (db != null) {
                // 1. Read every row where (rowid > lastRowID AND is_processed != 1)
                final ArrayList<SelectResult> results = db.getNewRows(lastRowID);
                log.debug("Inside: ProcessLintQueue - Reading the results.");

                // 2. Add each row to the threadpool.
                for (SelectResult res : results) {
            
                    log.debug("Inside: ProcessLintQueue - res.rowid: %d.", res.rowid);
                    // Check res.lr.hash exists in the threadpool.
                    // Add each res to the threadpool.
                    pool.execute(new LintTask(extensionConfig, res.lr));
                    // pool.submit(new LintTask(extensionConfig, res.lr));
                    // 3. Update lastRowID.
                    // Update the lastRowID because things might go bad in the middle.
                    if (res.rowid > lastRowID) lastRowID = res.rowid;
                }
                log.debug("Inside: ProcessLintQueue - Finished iterating through the results.");
                log.debug("Inside: ProcessLintQueue - lastrowid %d.", lastRowID);

                // We could also update lastRowID here with the rowID of the last record
                // in results. Foreach does not change the order.

                log.debug("Inside: ProcessLintQueue - Sleeping for %d seconds.", timeout);
                // 4. Sleep for X seconds.
                Thread.sleep(timeout * 1000);

                /// 5. Go to 1.
            }
        }

        log.error("Inside: ProcessLintQueue - Done with the ProcessLintQueue thread.");

        // Try to shutdown the pool.
        pool.shutdown();
        try {
            // TODO Timeout from config should appear here.
            pool.awaitTermination(60, TimeUnit.SECONDS);
            log.debug("Inside: ProcessLintQueue - All threads are terminated.");
        } catch (InterruptedException  e) {
            log.error("Inside: ProcessLintQueue - Could not terminate all threads: %s.", StringUtils.getStackTrace(e));
        }

        log.debug("Inside: ProcessLintQueue - Finished after shutdown.");
    }

    @Override
    public void run() {
        try {
            process();
        } catch (Exception e) {
            log.error("Inside: ProcessLintQueue - %s", StringUtils.getStackTrace(e));
        }
    }
    
}