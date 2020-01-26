package lint;

import static burp.BurpExtender.log;

import java.io.File;

import com.google.gson.GsonBuilder;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import utils.Exec;
import utils.StringUtils;

/**
 * BeautifyTask runs beautify on the input and stores the data at storagepath.
 */
public class Beautify {

    private String data;
    private Metadata metadata;
    // The directory where beautified files should be stored.
    private String storagePath = "";
    // The path to the js-beautify command, this comes from
    // extensionConfig.jsBeautifyBinaryPath.
    private String jsBeautifyCommandPath = "";

    public Beautify(
        String data,
        Metadata metadata,
        String storagePath,
        String jsBeautifyCommandPath
    ) {

        this.data = data;
        this.metadata = metadata;
        this.storagePath = storagePath;
        this.jsBeautifyCommandPath = jsBeautifyCommandPath;
        log.debug(
            "Created a new BeautifyTask.\nmetadata\n%s\nStorage path: %s",
            metadata.toString(),
            storagePath
        );
    }

    // 1. Beautifies the data.
    // 2. Stores the result in the storage path.
    // 3. Returns the result.
    public String execute() throws CustomException {

        Exec beautify = null;
        String jsFilePath = "";

        try {
            // Create the filename for this URL minus the extension.
            String jsFileName = metadata.getFileNameWithoutExtension();
            // Add the js extension.
            jsFilePath = FilenameUtils.concat(storagePath, jsFileName.concat(".js"));
            // Create the File to hold the beautified JavaScript.
            File jsFile = new File(jsFilePath);

            // Add the extracted JavaScript to data.
            StringBuilder sb = new StringBuilder(data);
            // Write the contents to a file in the storage path.
            FileUtils.writeStringToFile(jsFile, sb.toString(), "UTF-8");

            // Get the working directory of the js-beautify command. This is
            // usually the root of the `eslint-security` repo.
            String workingDirectory = FilenameUtils.getFullPath(jsBeautifyCommandPath);

            // Now we have a file with metadata and not-beautified JavaScript.
            // `js-beautify -f [filename] -r`
            // -r or --replace replace the same file with the beautified content
            // this will hopefully keep the metadata string intact (because it's
            // a comment).

            // Execute `js-beautify -f [filename] -r`
            String[] beautifyArgs = new String[] { "-f", jsFilePath, "-r" };
            beautify = new Exec(jsBeautifyCommandPath, beautifyArgs, workingDirectory);

            beautify.exec();
            log.debug("Executing %s", beautify.getCommandLine());
            log.debug("Output: %s", beautify.getStdOut());

            // Read the beautified JavaScript from jsFile. This is the return
            // value. However, we must first add the metadata string to the file
            // and rewrite it.
            String beautifiedJS = FileUtils.readFileToString(jsFile, "UTF-8");

            // TODO: This might be inefficient, might need to find a better
            // way to do it.

            // Create the metadata string.
            sb = new StringBuilder(metadata.toCommentString());
            // Add the beautified JavaScript to it.
            sb.append(beautifiedJS);
            // Write the data to the file.
            FileUtils.writeStringToFile(jsFile, sb.toString(), "UTF-8");

            // Return the beautified JavaScript without the metadata.
            return beautifiedJS;

        } catch (Exception e) {
            String status = StringUtils.getStackTrace(e);
            if (beautify != null) {
                if (StringUtils.isNotEmpty(beautify.getStdErr())) {
                    status += beautify.getStdOut();
                }
            }

            String errorMessage = String.format(
                "Error beautifying file %s in %s:\n%s",
                jsFilePath,
                metadata.toUglyString(),
                status
            );
            
            log.error(errorMessage);
            throw new CustomException(errorMessage);
        }
    }

    public String toString() {
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(this);
    }
}