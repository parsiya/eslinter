package utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.apache.commons.io.IOUtils;

/**
 * Exec
 */
public class Exec {

    private String workingDirectory;
    private String stdOut = "";
    private String stdErr = "";
    private CommandLine cmdLine;
    private int[] exitValues;

    // exitValues are valid exit values. By default, any exit value other than 0
    // is treated like an error by Commons-Exec. We can add others here. If you
    // set anything other than 0, be sure to include 0 because 0 will then be
    // treated like an error.
    public Exec(String cmd, String[] args, String workDir, int ...exitValues) {
        workingDirectory = workDir;
        this.exitValues = exitValues;

        // On Windows Commons-Exec needs the first item to be "cmd.exe" and then
        // "/c" and the rest of arguments.
        if (SystemUtils.IS_OS_WINDOWS) {
            cmdLine = new CommandLine("cmd.exe");
            cmdLine.addArgument("/c");
            // Add the original command.
            cmdLine.addArgument(cmd);
        } else {
            cmdLine = new CommandLine(cmd);
        }
        // Add the rest of the arguments.
        cmdLine.addArguments(args);
    }

    public int exec() throws ExecuteException, IOException {

        DefaultExecutor executor = new DefaultExecutor();

        // How to get both stdout and stderr.
        // https://stackoverflow.com/a/34571800
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PumpStreamHandler psh = new PumpStreamHandler(stdout, stderr);
        executor.setStreamHandler(psh);
        if (workingDirectory != null)
            executor.setWorkingDirectory(new File(workingDirectory));
        executor.setExitValues(exitValues);
        int exitValue = executor.execute(cmdLine);
        stdOut = stdout.toString().trim();
        stdErr = stderr.toString().trim();
        return exitValue;
    }

    public String getCommandLine() {
        return cmdLine.toString();
    }

    public String getStdOut() {
        return stdOut;
    }

    public String getStdErr() {
        return stdErr;
    }
    
    // Executes the Exec object but does not redirect stdout and stderr.
    public int execCmd() throws ExecuteException, IOException {
        DefaultExecutor executor = new DefaultExecutor();
        if (workingDirectory != null)
            executor.setWorkingDirectory(new File(workingDirectory));
        executor.setExitValues(exitValues);
        int exitValue = executor.execute(cmdLine);
        return exitValue; 
    }
}