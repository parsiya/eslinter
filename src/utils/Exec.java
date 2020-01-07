package utils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.commons.io.IOUtils;


/**
 * Exec
 */
public class Exec{

    // TODO Use this?
    private String command;
    private String[] arguments;
    private String workingDirectory;

    public Exec(String cmd, String[] args, String workDir) {
        command = cmd;
        arguments = args;
        workingDirectory = workDir;
    }
    
    public static String execute(String workingDir, String... commands) throws IOException {
        ArrayList<String> cmd = new ArrayList<String>();
        String[] cmdPrompt = new String[] {
            "cmd.exe", "/c"
        };
        cmd.addAll(Arrays.asList(cmdPrompt));
        cmd.addAll(Arrays.asList(commands));
        // cmd.add("cd"); // This helps us figure out where we are.
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(new File(workingDir));
        Process p = pb.start();
        String output = IOUtils.toString(p.getInputStream(), "UTF-8");
        String error = IOUtils.toString(p.getErrorStream(), "UTF-8");

        // TODO Find a better way of propagating the error results. Should we
        // throw an exception instead?
        // Make a custom exception and throw it with the message from error?
        String result = "";
        if (StringUtils.isNotEmpty(output)) result += output;
        if (StringUtils.isNotEmpty(error)) result += "---" + output;
               
        return result;

    }
}