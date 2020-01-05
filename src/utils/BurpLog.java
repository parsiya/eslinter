package utils;

import static burp.BurpExtender.callbacks;

/**
 * BurpLog does some simple logging to the extension's standard and error outputs
 */
public class BurpLog {

    private boolean debugMode = false;

    public BurpLog(boolean debugMode) {
        this.debugMode = debugMode;
    }

    // debug prints to standard output.
    public void debug(String format, Object ...args) {
        if (debugMode) StringUtils.printFormat(format, args);  
    }

    // error prints to error stream.
    public void error(String format, Object ...args) {
        StringUtils.errorFormat(format, args);
    }

    // Create a Burp alert.
    public void alert(String format, Object ...args) {
        String msg = String.format(format, args);
        callbacks.issueAlert(msg);
    }

    public boolean isDebugMode() {
        return debugMode;
    }

    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

}