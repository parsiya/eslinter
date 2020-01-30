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

    private String command;
    private String[] arguments;
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
        command = cmd;
        arguments = args;
        workingDirectory = workDir;
        this.exitValues = exitValues;

        // Add main command.
        cmdLine = new CommandLine(command);
        // Add arguments.
        for (String arg : arguments) {
            cmdLine.addArgument(arg);
        }
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
    
    public static String execute(String workingDir, String... commands) throws IOException {
        ArrayList<String> cmd = new ArrayList<String>();

        // Issue45.
        // 1. Detect OS.
        if (SystemUtils.IS_OS_WINDOWS) {
            // 2. If Windows, add "cmd.exe /c" to the start of the command.
            String[] winCmd = new String[] {
                "cmd.exe", "/c"
            };
            cmd.addAll(Arrays.asList(winCmd));
        }
        // 3. If *Nix and Mac, do nothing.

        // Add the rest of the command.
        cmd.addAll(Arrays.asList(commands));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        // If the working directory is null, it uses the one from the current
        // Java runtime.
        if (workingDir != null)
            pb.directory(new File(workingDir));
        Process p = pb.start();
        String output = IOUtils.toString(p.getInputStream(), StringUtils.UTF8);
        String error = IOUtils.toString(p.getErrorStream(), StringUtils.UTF8);

        // TODO Find a better way of propagating the error results. Should we
        // throw an exception instead?
        // Make a custom exception and throw it with the message from error?
        String result = "";
        if (StringUtils.isNotEmpty(output)) result += output;
        if (StringUtils.isNotEmpty(error)) result += "---" + output;
        
        return result;
    }
}