package database;

import static burp.BurpExtender.log;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.io.IOUtils;

import burp.BurpExtender;
import utils.StringUtils;

/**
 * Database
 */
public class Database {

    public Connection conn;
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
    public int addRow(
        String url, String referer, String hash, String beautified,
        String status, String results, int is_processed, int number_of_results
    ) throws SQLException, IOException {

        String addRowQuery = getResourceFile("/db/add_row.sql");

        PreparedStatement addRow = conn.prepareStatement(addRowQuery);
        addRow.setString(1, url);
        addRow.setString(2, referer);
        addRow.setString(3, hash);
        addRow.setString(4, beautified);
        addRow.setString(5, status);
        addRow.setString(6, results);
        addRow.setInt(7, is_processed);
        addRow.setInt(8, number_of_results);

        return addRow.executeUpdate();
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
        String content = IOUtils.toString(in, "UTF-8");
        in.close();
        return content;
    }
}