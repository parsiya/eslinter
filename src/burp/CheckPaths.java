package burp;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import utils.CustomException;
import utils.Exec;
import utils.StringUtils;
import java.nio.file.Files;

/**
 * CheckPaths has static methods to check paths in the config file.
 */
public class CheckPaths {

    // Returns true if all paths checkout, otherwise throws an exception with all
    // the errors.
    public static boolean checkAndCreatePaths(Config extensionConfig) throws CustomException {

        String err = "";

        // Create storagePath and check access.
        if (createDirectory(extensionConfig.storagePath)) {
            // storagePath is created or exists.
        } else {
            // storagePath was not created.
            // Check if we can write to it.
            if (!canWrite(extensionConfig.storagePath)) {
                err += String.format(
                    "Could not create or write to storagePath at %s.\n",
                    extensionConfig.storagePath
                );
            }
        }

        // Create eslintOutputPath and check access.
        if (createDirectory(extensionConfig.lintOutputPath)) {
            // eslintOutputPath is created or exists.
        } else {
            // eslintOutputPath was not created.
            // Check if we can write to it.
            if (!canWrite(extensionConfig.lintOutputPath)) {
                err += String.format(
                    "Could not create or write to eslintOutputPath at %s.\n",
                    extensionConfig.lintOutputPath
                );
            }
        }

        // Run eslintCommandPath to check if eslint exists.
        String runESLint = commandExists(extensionConfig.eslintCommandPath);
        if (StringUtils.isNotEmpty(runESLint)) {
            err += String.format(
                "Could not run ESLint at %s: %s.\n",
                extensionConfig.eslintCommandPath,
                runESLint
            );
        }

        // Run jsBeautifyCommandPath to check if eslint exists.
        String runJSBeautify = commandExists(
            extensionConfig.jsBeautifyCommandPath,
            1   // js-beautify returns 1 if run without any input or parameters.
        );

        if (StringUtils.isNotEmpty(runJSBeautify)) {
            err += String.format(
                "Could not run js-beautify at %s: %s.\n",
                extensionConfig.jsBeautifyCommandPath,
                runJSBeautify
            );
        }

        // Check if eslintConfigPath exists.
        if (!fileExists(extensionConfig.eslintConfigPath)) {
            err += String.format(
                "Could not find the ESLint rule file at %s.\n",
                extensionConfig.eslintConfigPath
            );
        }

        // Check if the directory with the database is writable. Connect will
        // take care of creating the file.
        String dbDirectory = StringUtils.getParentDirectory(extensionConfig.dbPath);
        if (createDirectory(dbDirectory)) {
            // dbDirectory is created or exists.
        } else {
            // dbDirectory was not created, check if we can write to it.
            if (!canWrite(dbDirectory)) {
                err += String.format(
                    "Could not write to the database directory at %s.\n",
                    dbDirectory
                );
            }   
        }

        if (StringUtils.isNotEmpty(err)) {
            throw new CustomException(err);
        } else {
            return true;
        }
    }

    // Return an empty string if command exists and executes successfully.
    // Otherwise, it returns the exception.
    private static String commandExists(String path, int ...exitValues) {
        Exec cmd = new Exec(
            path,
            new String[] {""},
            StringUtils.getParentDirectory(path),
            exitValues
        );

        try {
            cmd.exec();
        } catch (Exception e) {
            return StringUtils.getStackTrace(e);
        }
        return "";
    }


    // Returns true if the application can write to the directory or file.
    private static boolean canWrite(String dir) {
        Path p = Paths.get(dir);
        return Files.isWritable(p);
    }

    // Creates the directory in dir. Returns true if directory was created. What
    // does it return if it already existed?
    private static boolean createDirectory(String dir) {
        File f = new File(dir);
        return f.mkdirs();
    }

    // Returns true if a file exists.
    public static boolean fileExists(String file) {
        return new File(file).exists();
    }
}