package detective;

/**
 * FilenameUtils contains copied and modified utilities from the
 * Apache commons-io.FilenameUtils package.
 * https://github.com/apache/commons-io/blob/master/src/main/java/org/apache/commons/io/FilenameUtils.java
 * Windows support was not needed and removed.
 */
public class FilenameUtils {

    private static final String EMPTY_STRING = "";
    private static final int NOT_FOUND = -1;

    public static String getExtension(final String fileName) throws IllegalArgumentException {
        if (fileName == null) {
            return null;
        }
        final int index = indexOfExtension(fileName);
        if (index == NOT_FOUND) {
            return EMPTY_STRING;
        }
        return fileName.substring(index + 1);
    }

    private static int indexOfExtension(final String fileName) {
        if (fileName == null) {
            return NOT_FOUND;
        }
        final int extensionPos = fileName.lastIndexOf(".");
        final int lastSeparator = indexOfLastSeparator(fileName);
        return lastSeparator > extensionPos ? NOT_FOUND : extensionPos;
    }

    private static int indexOfLastSeparator(final String fileName) {
        if (fileName == null) {
            return NOT_FOUND;
        }
        return fileName.lastIndexOf("/");
    }
}