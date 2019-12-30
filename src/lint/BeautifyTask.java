package lint;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import burp.BurpExtender;
import burp.Config;
import utils.Exec;
import utils.StringUtils;

/**
 * ParallelBeautify
 */
public class BeautifyTask implements Runnable {

    private Beautify beautifier;
    private String data;
    private Metadata metadata;
    private boolean beautified;
    private String storagePath = "";

    public BeautifyTask(Beautify beautifier, String data, Metadata metadata,
        String storagePath) throws BeautifyNotFound {

        this.beautifier = beautifier;
        this.data = data;
        this.beautified = false;
        this.metadata = metadata;
        this.storagePath = storagePath;
    }

    @Override
    public void run() {
        // Beautify the data and return a string.
        String output = beautifier.beautify(data);
        beautified = StringUtils.isEmpty(output) ? false : true;
        metadata.setBeautified(beautified);

        // Filename will be "filename_from_URL[minus extension]-hash.js".
        String jsFileName = "";
        try {
            jsFileName = StringUtils.getURLBaseName(metadata.getUrl());
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
        StringWriter sw = new StringWriter();
        sw.write("/*\n");
        sw.write(metadata.toString());
        sw.write("\n*/\n\n");

        if (beautified) {
            // If successful, store the results in a file.
            sw.write(output);
        } else {
            // If not successful, store the original content.
            sw.write(data);
        }

        try {
            // Write the contents to the file.
            FileUtils.writeStringToFile(jsFile, sw.toString(), "UTF-8");
        } catch (IOException e) {
            // If things go wrong print the exception and return.
            StringUtils.getStackTrace(e);
            return;
        }
        // Execute ESLint with Exec on the file.
        String eslintDirectory = FilenameUtils.getFullPath(Config.ESLintBinaryPath);

        // Create the output filename and path.
        // Output filename is the same as the original filename with "-out".
        String eslintResultFileName = jsFileName.concat("-out.js");
        String eslintResultFilePath = FilenameUtils.concat(Config.ESLintOutputPath, eslintResultFileName);

        try {
            // TODO: Change this.
            String res = Exec.execute(eslintDirectory, Config.ESLintBinaryPath,
                "-c", Config.ESLintConfigPath, "-f","codeframe", "--no-color",
                // "-o", eslintResultFilePath,
                "--no-inline-config", jsFilePath);
            
            // Write res to output file.
            FileUtils.writeStringToFile(new File(eslintResultFilePath), res, "UTF-8");

            // Regex to separate the findings.
            // (.*?)\n\n\n

            // String ptrn = "(.*?)\n\n\n";
            // int flags = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;

            // Pattern pt = Pattern.compile(ptrn, flags);
            // Matcher mt = pt.matcher(res);

            // // Now each item in the matcher is a separate finding.
        
            // // Add each finding as a finding to Burp.

            BurpExtender.callbacks.printOutput(String.format("Results file: %s", eslintResultFilePath));
            BurpExtender.callbacks.printOutput(String.format("Input file: %s", jsFilePath));
            BurpExtender.callbacks.printOutput(String.format("ESLint execution result: %s\n", res));
            BurpExtender.callbacks.printOutput("----------");

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
    }
}