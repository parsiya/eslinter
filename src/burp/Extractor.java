package burp;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import utils.StringUtils;


/**
 * Extractor
 */
public class Extractor {

    private static String pattern = "<script[^>]*>(.*?)<\\/script>";
    private static int flags = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;

    public static String getJS(byte[] data) {
        Pattern pt = Pattern.compile(pattern, flags);
        Matcher mt = pt.matcher(StringUtils.bytesToString(data));

        StringBuilder sb = new StringBuilder();
        while (mt.find()) {
            if ( !StringUtils.isEmpty(mt.group(1)) ) {
                sb.append("\n");
                sb.append(mt.group(1));
            }
        }
        return sb.toString();
    }
}
