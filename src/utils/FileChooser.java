package utils;

import static burp.BurpExtender.callbacks;
import static utils.StringUtils.isNotEmpty;

import java.awt.Component;
import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;


/**
 * FileChooser
 */
public class FileChooser extends JFileChooser {

    @Override
    public void approveSelection() {
                
        File selected = getSelectedFile();
        if (selected.exists()) {
            int ret = JOptionPane.showConfirmDialog(
                this.getParent(),
                "Overwrite existing file " + selected + "?",
                "File exists",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            if (ret == JOptionPane.OK_OPTION)
                super.approveSelection();
        } else {
            super.approveSelection();
        }
    }

    // Parent = parent swing component.
    // startingPath = where to start.
    // title = dialog title.
    // extension (e.g., json) = the extension to look for.
    // returns null if the dialog is cancelled, treat the result accordingly.
    public static File saveFile(Component parent, String startingPath, String title,
            String extension) {

        // Issue27, overwrite dialog prompt.
        // JFileChooser fc = new JFileChooser();
        FileChooser fc = new FileChooser();

        // If starting path is set, use it.
        if (isNotEmpty(startingPath))
            fc.setCurrentDirectory(new File(startingPath));

        // If title is set, use it.
        if (isNotEmpty(title))
            fc.setDialogTitle(title);

        // If extension is set, create the file filter.
        if (isNotEmpty(extension)) {
            // "JSON Files (*.json)"
            String extFilterString = String.format("%s Files (*.%s)", extension.toUpperCase(),
                    extension.toLowerCase());
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
        if (retVal != JFileChooser.APPROVE_OPTION)
            return null;

            return fc.getSelectedFile();
    }

    // Parent = parent swing component.
    // startingPath = where to start.
    // title = dialog title.
    // extension (e.g., json) = the extension to look for.
    // returns null if the dialog is cancelled, treat the result accordingly.
    public static File openFile(Component parent, String startingPath,
        String title, String extension) {

        JFileChooser fc = new JFileChooser();
        // If starting path is set, use it.
        if (isNotEmpty(startingPath))
            fc.setCurrentDirectory(new File(startingPath));
        
        // If title is set, use it.
        if (isNotEmpty(title))
            fc.setDialogTitle(title);

        // If extension is set, create the file filter.
        if (isNotEmpty(extension)) {
            // "JSON Files (*.json)"
            String extFilterString = String.format(
                "%s Files (*.%s)",
                extension.toUpperCase(),extension.toLowerCase()
            );
            String[] extFilterList = new String[] {extFilterString};
            FileNameExtensionFilter ff =
                new FileNameExtensionFilter(extFilterString, extFilterList);
            fc.addChoosableFileFilter(ff);
        }
        // Only choose files.
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        // Show the dialog and store the return value.
        int retVal = fc.showOpenDialog(parent); // The only difference with saveFile.
        // If the dialog was cancelled, return null.
        if (retVal != JFileChooser.APPROVE_OPTION)
            return null;
        
        return fc.getSelectedFile();
    }

    // Get last working directory, should be "lastdir" in extension settings.
    public static String getLastWorkingDirectory() {
        String lastdir = callbacks.loadExtensionSetting("lastdir");
        if (lastdir == null)
            return Constants.EMPTY_STRING;

        return lastdir;
    }

    public static void setLastWorkingDirectory(String lastdir) {
        callbacks.saveExtensionSetting("lastdir", lastdir);
    }

    // Opens a JFileChooser dialog to select a directory to do stuff.
    // Parent = parent swing component.
    // startingPath = where to start.
    // title = dialog title.
    // returns null if the dialog is cancelled, treat the result accordingly.
    public static File saveDirectory(Component parent, String startingPath, String title) {

        JFileChooser fc = new JFileChooser();
        // If starting path is set, use it.
        if (isNotEmpty(startingPath))
            fc.setCurrentDirectory(new File(startingPath));

        // If title is set, use it.
        if (isNotEmpty(title))
            fc.setDialogTitle(title);

        // Only choose files.
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        // Show the dialog and store the return value.
        int retVal = fc.showSaveDialog(parent); // The only difference with openFile.
        // If the dialog was cancelled, return null.
        if (retVal != JFileChooser.APPROVE_OPTION)
            return null;

        // Also check if getSelectedFile() works.
        // return fc.getCurrentDirectory();
        return fc.getSelectedFile();
    }

}
