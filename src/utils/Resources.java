package utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;


/**
 * Resources
 */
public class Resources {

    // Reads a resource and returns it as a string.
    // Remember to designate files with a /.
    // E.g., to get "resources/whatever.txt", call getResourceFile("/whatever.txt").
    // E.g., "resources/path/whatever.txt" -> getResourceFile("/path/whatever.txt").
    public static String getResourceFile(Class cls, String name) throws IOException {
        InputStream in = cls.getResourceAsStream(name); 
        String content = IOUtils.toString(in, "UTF-8");
        in.close();
        return content;
    }
}