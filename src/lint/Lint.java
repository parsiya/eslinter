package lint;

import static burp.BurpExtender.log;

import java.io.File;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import burp.Config;
import linttable.LintResult;
import utils.Exec;
import utils.StringUtils;

/**
 * LintTask lints a bunch of JavaScript text and returns the result.
 */
public class Lint {

    private Metadata metadata;
    private String javascript = "";
    private Config extensionConfig;

    public Lint(Metadata metadata, String javascript, Config extensionConfig) {
        this.metadata = metadata;
        this.javascript = javascript;
        this.extensionConfig = extensionConfig;
    }

    // Runs the linter.
    public LintResult execute() throws IOException {

        // ESLint command's working directory.
        String eslintDirectory = FilenameUtils.getFullPath(extensionConfig.eslintBinaryPath);

        // Store the JavaScript in a temp file. The method takes care of
        // filename uniqueness.
        File tempJS = File.createTempFile("eslint", ""); // Throws IOException.
        String tempJSPath = tempJS.getAbsolutePath();
        // Store the data in the temp file.
        FileUtils.write(tempJS, javascript, "UTF-8");

        // Create the output filename for this data.
        String eslintResultFileName = metadata.getFileNameWithoutExtension().concat("-linted.js");
        // Create the full path for the output file.
        String eslintResultFilePath = FilenameUtils.concat(extensionConfig.eslintOutputPath, eslintResultFileName);

        // Create linter args to run ESLint.
        String[] linterArgs = new String[] { "-c", extensionConfig.eslintConfigPath, "-f", "codeframe",
        "--no-color",
        // "-o", eslintResultFileName, // We can use this if we want to create the
        // output file manually.
        "--no-inline-config", tempJSPath };

        // Create the ESLint Exec.
        Exec linter = new Exec(
            extensionConfig.eslintBinaryPath,
            linterArgs,
            eslintDirectory,
            0, 1, 2 // Exit values for ESLint.
        );

        log.debug("Executing %s", linter.getCommandLine());
        int exitVal = linter.exec();
        // If exitVal is 2, it means there was a parsing error. In this case
        // we do not want an exception but we will log the error.
        String results = linter.getStdOut();
        String err = linter.getStdErr();
        
        String status = "";
        if (exitVal == 2 || exitVal == 1) {
            status += err;
        }

        // Add the metadata to the output file contents.
        StringBuilder eslintResults = new StringBuilder(metadata.toCommentString());
        // Add the ESLint results.
        eslintResults.append(results);

        // Write the results to the output file.
        FileUtils.writeStringToFile(new File(eslintResultFilePath), eslintResults.toString(), "UTF-8");

        // Process results

        // Regex to separate the results.
        // (.*?)\n\n\n

        String ptrn = "(.*?)\n\n\n";
        int flags = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;
        Pattern pt = Pattern.compile(ptrn, flags);
        Matcher mt = pt.matcher(results);

        // Now each item in the matcher is a separate finding.
        // TODO Do something with each finding.
        int numResults = (int) mt.results().count();

        log.debug("Results file: %s", eslintResultFilePath);
        log.debug("Input file: %s", tempJSPath);

        if (StringUtils.isEmpty(status)) status = "Linted";
        
        // Start creating the returning LintResult.
        LintResult lr = new LintResult(
            metadata,
            metadata.getHost(),
            metadata.getURL(),
            metadata.getHash(),
            javascript,
            status,
            results,
            1,
            numResults
        );

        return lr;
    }
}