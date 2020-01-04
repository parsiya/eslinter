package utils;

import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.Component;
import static utils.StringUtils.isNotEmpty;
import static burp.BurpExtender.callbacks;

/**
 * FileChooser
 */
public class FileChooser {

    // Parent = parent swing component.
    // startingPath = where to start, load this from the extension settings?
    // title = dialog title.
    // extension (e.g., json) = the extension to look for.
    // returns null if the dialog is cancelled, treat the result accordingly.
    public static File saveFile(Component parent, String startingPath,
        String title, String extension) {

        JFileChooser fc = new JFileChooser();
        // If starting path is set, use it.
        if (isNotEmpty(startingPath)) {
            fc.setCurrentDirectory(new File(startingPath));
        }
        // If title is set, use it.
        if (isNotEmpty(title)) {
            fc.setDialogTitle(title);
        }
        // If extension is set, create the file filter.
        if (isNotEmpty(extension)) {
            // "JSON Files (*.json)"
            String extFilterString = String.format("%s Files (*.%s)",
                extension.toUpperCase(), extension.toLowerCase());
            String[] extFilterList = new String[] {extFilterString};
            FileNameExtensionFilter ff =
                new FileNameExtensionFilter(extFilterString, extFilterList);
            fc.addChoosableFileFilter(ff);
        }
        // Only choose files.
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        // Show the dialog and store the return value.
        int retVal = fc.showSaveDialog(parent);
        // If the dialog was cancelled, return null.
        if (retVal != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        return fc.getSelectedFile();
    }

    // Get last working directory, should be "lastdir" in extension settings.
    public static String getLastWorkingDirectory() {
        String lastdir = callbacks.loadExtensionSetting("lastdir");
        if (lastdir == null) return Constants.EMPTY_STRING;
        return lastdir;
    }

    public static void setLastWorkingDirectory(String lastdir) {
        callbacks.saveExtensionSetting("lastdir", lastdir);
    }
}