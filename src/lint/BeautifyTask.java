package lint;

import static burp.BurpExtender.extensionConfig;
import static burp.BurpExtender.log;

import java.io.File;
import java.io.IOException;

import com.google.gson.GsonBuilder;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import utils.Exec;
import utils.StringUtils;

/**
 * BeautifyTask
 */
public class BeautifyTask implements Runnable {

    // private Beautify beautifier;
    private String data;
    private Metadata metadata;
    private String storagePath = "";

    public BeautifyTask(String data, Metadata metadata, String storagePath) {

        this.data = data;
        this.metadata = metadata;
        this.storagePath = storagePath;
        log.debug("Created a new BeautifyTask.\nmetadata\n%s\nStorage path: %s",
            metadata.toString(), storagePath);
    }

    @Override
    public void run() {

        // Filename will be "filename_from_URL[minus extension]-[hash].js".
        String jsFileName = "";
        try {
            jsFileName = StringUtils.getURLBaseName(metadata.getUrl());
            jsFileName = jsFileName.replaceAll("=", "-");
            if (!StringUtils.isEmpty(jsFileName)) {
                // If the URL does not end in a file jsFIleName will be empty.
                // If it's not empty, we add the "-" to it.
                jsFileName = jsFileName.concat("-");
            }
            // If jsFileName was empty do nothing.
        } catch (Exception e) {
            // If URL cannot be converted to a string use the hash.
            // Technically this should not happen because the URL in the
            // metadata should be well-formed but who knows.
        }
        // Attach the hash and the extension.
        jsFileName = jsFileName.concat(metadata.getHash());

        // Add the js extension.
        String jsFilePath = FilenameUtils.concat(storagePath, jsFileName.concat(".js"));
        // Create a File.
        File jsFile = new File(jsFilePath);

        // Create the metadata string.
        StringBuilder sb = new StringBuilder(metadata.toCommentString());
        // Add the extracted JavaScript.
        sb.append(data);

        try {
            // Write the contents to the file.
            FileUtils.writeStringToFile(jsFile, sb.toString(), "UTF-8");
        } catch (IOException e) {
            // If things go wrong print the exception and return.
            StringUtils.getStackTrace(e);
            return;
        }

        // Now we have a file with metadata and not-beautified JavaScript.
        // js-beautify -f [filename] -r
        // -r or --replace replace the same file with the beautified content
        // this will hopefully keep the metadata string intact (because it's a
        // comment).

        // Eslint and js-beautify directories are the same because they are
        // installed in the same location.
        String eslintDirectory = FilenameUtils.getFullPath(extensionConfig.eslintBinaryPath);
        String[] beautifyArgs = new String[] {
            "-f", jsFilePath, "-r"
        };
        Exec beautify = new Exec(
            extensionConfig.jsBeautifyBinaryPath,
            beautifyArgs,
            eslintDirectory
        );

        try {
            int exitVal = beautify.exec();
            log.debug("Executing %s", beautify.getCommandLine());
            log.debug("Output: %s", beautify.getStdOut());

        } catch (Exception e) {
            log.error(StringUtils.getStackTrace(e));
            log.error(beautify.getStdErr());
            return;
        }

        // Now we can read the file to get the beautified data if needed.

        // Execute ESLint with Exec on the file.

        // Create the output filename and path.
        // Output filename is the same as the original filename with "-out".
        String eslintResultFileName = jsFileName.concat("-out.js");
        String eslintResultFilePath = FilenameUtils.concat(extensionConfig.eslintOutputPath, eslintResultFileName);

        String[] linterArgs = new String[] {
            "-c", extensionConfig.eslintConfigPath,
            "-f", "codeframe",
            "--no-color",
            // "-o", eslintResultFileName, // Use this if we want to create the output file manually.
            "--no-inline-config",
            jsFilePath
        };
        Exec linter = new Exec(
            extensionConfig.eslintBinaryPath,
            linterArgs,
            eslintDirectory
        );

        // try {
        //     log.debug("Executing %s", linter.getCommandLine());
        //     int exitVal = linter.exec();
        //     String result = linter.getStdOut();

        //     // Add the metadata to the output file.
        //     sb = new StringBuilder(metadata.toCommentString());
        //     sb.append(result);

        //     FileUtils.writeStringToFile(
        //         new File(eslintResultFilePath), sb.toString(), "UTF-8"
        //     );
            
        //     // Regex to separate the findings.
        //     // (.*?)\n\n\n

        //     // String ptrn = "(.*?)\n\n\n";
        //     // int flags = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;
        //     // Pattern pt = Pattern.compile(ptrn, flags);
        //     // Matcher mt = pt.matcher(result);

        //     // Now each item in the matcher is a separate finding.
        //     // TODO Do something with each finding.

        //     log.debug("Results file: %s", eslintResultFilePath);
        //     log.debug("Input file: %s", jsFilePath);
        //     log.debug("----------");

        // } catch (Exception e) {
        //     // TODO Auto-generated catch block
        //     log.error(StringUtils.getStackTrace(e));
        //     log.error(linter.getStdErr());
        //     return;
        // }
    }

    public String toString() {
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(this);
    }
}