package utils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;


/**
 * Exec
 */
public class Exec{

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
        // cmd.add("cd");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(new File(workingDir));
        String output = IOUtils.toString(pb.start().getInputStream(), "UTF-8");
        // Process p = pb.inheritIO().start();
        return output;

    }
}