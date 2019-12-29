package lint;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import burp.BurpExtender;
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

        String path = storagePath.concat(metadata.getHash().concat(".js"));
        File outFile = new File(path);

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
            FileUtils.writeStringToFile(outFile, sw.toString(), "UTF-8");
            // Seems like this has no effect.
            // sw.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            StringUtils.getStackTrace(e);
            return;
        }
        // Execute ESLint with Exec on the file.

        // Hardcoded for now.
        // TODO Move to config and ultimately configurable via the UI.
        String eslintDirectory = "C:\\Users\\IEUser\\Desktop\\git\\eslint-security-scanner-configs";
        String eslintPath = FilenameUtils.concat(eslintDirectory, "node_modules\\.bin\\eslint");
        String configPath = FilenameUtils.concat(eslintDirectory, "eslintrc-light.js");

        try {
            String res = Exec.execute(eslintDirectory, eslintPath, "-c", configPath, "-f",
                    "codeframe", "--no-color", "-o",
                    storagePath.concat(metadata.getHash().concat("-out.js")), path);
            BurpExtender.callbacks.printOutput(String.format("outfile: %s\n", storagePath.concat(metadata.getHash().concat("-out.js"))));
            BurpExtender.callbacks.printOutput(String.format("infile: %s\n", path));
            BurpExtender.callbacks.printOutput(String.format("res: %s\n", res));

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
    }
}