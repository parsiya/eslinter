package database;

import static burp.BurpExtender.log;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import org.apache.commons.io.IOUtils;
import burp.BurpExtender;
import lint.Metadata;
import linttable.LintResult;
import utils.StringUtils;

/**
 * Database
 */
public class Database {

    private Connection conn;
    // TODO Remove this if it's not used.
    private String path;

    // Creates the database and populates the connection.
    // If the path does not exist, it will be created.
    public Database(String path) throws SQLException, IOException {
        // To fix the "No suitable driver found for jdbc:sqlite:" error.
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            log.error(StringUtils.getStackTrace(e));
        }
        // Need "//"" before the full path.
        // https://stackoverflow.com/a/32799328
        conn =  DriverManager.getConnection("jdbc:sqlite://" + path);

        // Run the table create statements and add the triggers.
        createTable();
        addTriggers();

        this.path = path;
    }

    // Executes a statement on the datavase and returns the boolean result.
    // This can be used to create tables or add triggers.
    public boolean executeStatement(String statement) throws SQLException {

        Statement stmt = conn.createStatement();
        return stmt.execute(statement);
    }

    // Executes the create table script.
    private boolean createTable() throws IOException, SQLException {
        return executeResourceFile("/db/create_table.sql");
    }

    // Adds the triggers to the table.
    private void addTriggers() throws IOException, SQLException {
        executeResourceFile("/db/update_hash-trigger.sql");
        executeResourceFile("/db/check_already_processed-trigger.sql");
    }

    // Read the sql file from resources and execute it as a statement.
    private boolean executeResourceFile(String name) throws IOException, SQLException {

        // Get the contents of the file as a string.
        String content = getResourceFile(name);
        // Execute it as a statement.
        return executeStatement(content);
    }

    // Adds a new row to the eslint table and returns the number of updated
    // records which should usually be 1.
    public int addRow(LintResult lr) throws SQLException, IOException {

        String addRowQuery = getResourceFile("/db/add_row.sql");

        /*
            INSERT INTO eslint
            (metadata, url, hash, beautified_javascript, status, results, is_processed, number_of_results)
            VALUES (?,?,?,?,?,?,?,?);
        */

        PreparedStatement addRow = conn.prepareStatement(addRowQuery);
        addRow.setString(1, lr.metadata.toUglyString());
        addRow.setString(2, lr.url);
        addRow.setString(3, lr.hash);
        addRow.setString(4, lr.beautifiedJavaScript);
        addRow.setString(5, lr.status);
        addRow.setString(6, lr.results);
        addRow.setInt(7, lr.isProcessed);
        addRow.setInt(8, lr.numResults);

        int res = addRow.executeUpdate();
        addRow.closeOnCompletion();
        return res;
    }

    // Returns all rows in the database where
    // (rowid > lastRowID AND is_processed !=1).
    public ArrayList<SelectResult> getNewRows(long lastRowID) throws IOException, SQLException {
        
        String getNewRowsQuery = getResourceFile("/db/get_new_rows.sql");
        PreparedStatement getNewRows = conn.prepareStatement(getNewRowsQuery);
        getNewRows.setLong(1, lastRowID);
        ResultSet rs = getNewRows.executeQuery();

        /*
            SELECT * FROM eslint
            WHERE
                rowid > (?) AND is_processed != 1
            ORDER BY
                rowid
        */

        ArrayList<SelectResult> results = new ArrayList<SelectResult>();
        // Now we can process the results.
        while (rs.next()) {

            // ResultSetMetaData rsmd = rs.getMetaData();
            // int columnCount = rsmd.getColumnCount();

            // for (int i = 1; i <= columnCount; i++) {
            //     String colName = rsmd.getColumnName(i);
            //     String colLabel = rsmd.getColumnLabel(i);
            //     // Object colVal = rs.getOb
            //     log.debug("zz %d - %s - %s", i, colName, colLabel);
            // }

            // Fingers crossed this works.
            String metadataString = rs.getString("metadata");
            Metadata metadata = Metadata.fromString(metadataString);

            LintResult lr = new LintResult(
                metadata,
                metadata.getHost(),
                rs.getString("url"),
                rs.getString("hash"),
                rs.getString("beautified_javascript"),
                rs.getString("status"),
                rs.getString("results"),
                rs.getInt("is_processed"),
                rs.getInt("number_of_results")
            );
            results.add(new SelectResult(rs.getLong("rowid"), lr));
        }

        // Close the statement.
        getNewRows.closeOnCompletion();
        return results;
    }

    public int updateRow(LintResult lr) throws IOException, SQLException {

        String updateRowQuery = getResourceFile("/db/update_row.sql");

        /* 
            UPDATE eslint
            SET
                beautified_javascript = ?,
                status = ?,
                results = ?,
                is_processed = ?,
                number_of_results = ?
            WHERE
                metadata = ?
        */

        PreparedStatement updateRow = conn.prepareStatement(updateRowQuery);
        updateRow.setString(1, lr.beautifiedJavaScript);
        updateRow.setString(2, lr.status);
        updateRow.setString(3, lr.results);
        updateRow.setInt(4, lr.isProcessed);
        updateRow.setInt(5, lr.numResults);
        
        // WHERE metadata = ?
        updateRow.setString(6, lr.metadata.toUglyString());

        int res = updateRow.executeUpdate();
        updateRow.closeOnCompletion();
        return res;
    }

    public ArrayList<LintResult> getAllRows() throws IOException, SQLException {

        String getAllRowsQuery = getResourceFile("/db/get-all_rows.sql");

        PreparedStatement getAllRows = conn.prepareStatement(getAllRowsQuery);
        ResultSet rs = getAllRows.executeQuery();
        
        ArrayList<LintResult> results = new ArrayList<LintResult>();
        // Now we can process the results.
        while (rs.next()) {

            String metadataString = rs.getString("metadata");
            Metadata metadata = Metadata.fromString(metadataString);

            LintResult lr = new LintResult(
                metadata,
                metadata.getHost(),
                rs.getString("url"),
                rs.getString("hash"),
                rs.getString("beautified_javascript"),
                rs.getString("status"),
                rs.getString("results"),
                rs.getInt("is_processed"),
                rs.getInt("number_of_results")
            );
            results.add(lr);
        }

        getAllRows.closeOnCompletion();
        return results;
    }

    public void close() throws SQLException {
        conn.close();
    }

    // Reads a resource file and returns the content as a string. This can be
    // used to read sql files from the resources directory.
    // Reads a resource and returns it as a string.
    // Remember to designate files with a /.
    // E.g., to get "resources/whatever.txt", call getResourceFile("/whatever.txt").
    // E.g., "resources/path/whatever.txt" -> getResourceFile("/path/whatever.txt").
    private static String getResourceFile(String name) throws IOException {

        InputStream in = BurpExtender.class.getResourceAsStream(name); 
        String content = IOUtils.toString(in, StringUtils.UTF8);
        in.close();
        return content;
    }
}