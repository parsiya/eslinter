package lint;

// Custom exception to return Beautify errors.
public class CustomException extends Exception {

    public CustomException(String errorMessage) {
        super(errorMessage);
    }
}