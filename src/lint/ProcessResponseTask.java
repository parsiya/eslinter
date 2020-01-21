package lint;

import static burp.BurpExtender.log;
import static burp.BurpExtender.mainTab;
import static burp.BurpExtender.db;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import com.google.gson.GsonBuilder;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import burp.Config;
import linttable.LintResult;
import utils.Exec;
import utils.StringUtils;

/**
 * ProcessResponseTask processes one intercepted response.
 */
public class ProcessResponseTask implements Runnable {

    private String data;
    private Metadata metadata;
    private Config extensionConfig;

    public ProcessResponseTask(
        String data, Metadata metadata, Config config) {

        this.data = data;
        this.metadata = metadata;
        this.extensionConfig = config;
        log.debug(
            "Created a new ProcessResponseTask.\nmetadata\n%s\nStorage path: %s",
            metadata.toString(),
            extensionConfig.storagePath
        );
    }

    @Override
    public void run() {

        String status = "", beautifiedJavaScript = "";

        try {
            // Create a beautify task which beautifies the file and stores it.
            Beautify jsBeautify = new Beautify(
                data,
                metadata,
                extensionConfig.storagePath,
                extensionConfig.jsBeautifyBinaryPath
            );
            // The return result contains beautified JavaScript.
            beautifiedJavaScript = jsBeautify.execute();
        } catch (CustomException e) {
            log.error("%s", e.getMessage());
            status = e.getMessage();
        }

        // Now we need to add the data to the database and table.
        
        // Check status, if it's empty then there has been no errors.
        if (StringUtils.isEmpty(status)) {
            status = "Beautified";
        }

        // Add the data to the table.
        try {
            db.addRow(
                metadata.getURL(),      // url
                metadata.getReferer(),  // referer
                metadata.getHash(),     // hash
                beautifiedJavaScript,   // beautified JavaScript in jsFilePath
                status,                 // status
                "",                     // eslint result
                0,                      // is_processed
                0                       // number_of_results
            );
            log.debug("Added row for hash %s to the database.", metadata.getHash());
            
            // If the row already exists in the table, we will not reach
            // here and as a result duplicate rules will not be added to the
            // table.

            // Create the LintResult and add to the table.
            final LintResult lr = new LintResult(
                metadata.getHost(),
                metadata.getURL(),
                status,
                0,
                ""
            );

            SwingUtilities.invokeLater(new Runnable () {
                @Override
                public void run () {
                    mainTab.lintTable.add(lr);
                }
            });
            log.debug("Added the request to the table.");
        } catch (SQLException | IOException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                log.debug(
                    "Row %s already exists. Skipping adding the row.",
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