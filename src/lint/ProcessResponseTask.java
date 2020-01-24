package lint;

import static burp.BurpExtender.db;
import static burp.BurpExtender.log;
import java.io.IOException;
import java.sql.SQLException;
import com.google.gson.GsonBuilder;
import linttable.LintResult;
import utils.StringUtils;

/**
 * ProcessResponseTask processes one intercepted response.
 */
public class ProcessResponseTask implements Runnable {

    private String data;
    private Metadata metadata;

    public ProcessResponseTask(
        String data, Metadata metadata) {

        this.data = data;
        this.metadata = metadata;
        log.debug(
            "Created a new ProcessResponseTask.\nmetadata: %s",
            metadata.toUglyString()
        );
    }

    @Override
    public void run() {

        try {

            // Create a LintResult to store in the table.
            LintResult lr = new LintResult(
                metadata,           // metadata
                metadata.getHost(), // host
                metadata.getURL(),  // url
                metadata.getHash(), // hash
                data,               // javascript -- not beautified yet
                "Not Beautified",   // status
                "",                 // eslint results
                0,                  // is_processed
                0                   // number of results
            );
            
            // Add the data to the table.
            db.addRow(lr);

            log.debug("Added new request to the table: %s", metadata.toUglyString());
            
            // If the row already exists in the table, we will not reach here.

        } catch (SQLException | IOException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                log.debug(
                    "Row %s already exists. Skipping.",
                    metadata.toUglyString()
                );
            } else {
                log.error(StringUtils.getStackTrace(e));
            }
        }
    }

    public String toString() {
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(this);
    }
}