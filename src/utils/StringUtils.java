package utils;

import static burp.BurpExtender.callbacks;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.apache.commons.io.FilenameUtils;

/**
 * StringUtils
 */
public class StringUtils {

    // Print to extension output.
    public static void print(String data) {
        callbacks.printOutput(data);
    }

    // Print with format string.
    public static void printFormat(String format, Object... args) {
        print(String.format(format, args));
    }

    // Print to extension error.
    public static void error(String data) {
        callbacks.printError(data);
    }

    // Print errors with format string.
    public static void errorFormat(String format, Object... args) {
        error(String.format(format, args));
    }

    public static String bytesToString(byte[] data) {
        return new String(data);
    }

    public static byte[] stringToBytes(String data) {
        return data.getBytes();
    }

    public static String getStackTrace(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    public static void printStackTrace(Exception e) {
        error(getStackTrace(e));
    }

    // Returns the filename of a string URL without the extension.
    // https://stackoverflow.com/a/17167743
    public static String getURLBaseName(String url) throws MalformedURLException {
        return FilenameUtils.getBaseName(new URL(url).getPath());
    }

    // Base64 encode and decode methods that return a String instead of byte[].
    public static String base64Encode(String plaintext) {
        return Base64.getEncoder().encodeToString(stringToBytes(plaintext));
    }

    public static String base64Decode(String encoded) {
        byte[] decodedBytes = Base64.getDecoder().decode(encoded);
        return bytesToString(decodedBytes);
    }

    // Returns true if item is in arr. Does case-insensitive comparison.
    /**
     * For case-sensitive contains do: List<String> lst =
     * java.util.Arrays.asList(arr); return lst.contains(item);
     */
    public static boolean arrayContains(String item, String[] arr) {
        for (String arrayItem : arr) {
            if (item.equalsIgnoreCase(arrayItem))
                return true;
        }
        return false;
    }

    // Returns the parent directory of a full path.
    public static String getParentDirectory(String fullpath) {
        return FilenameUtils.getFullPath(fullpath);
        // File f = new File(fullpath);
        // return f.getParent();
    }

    // TODO Remove this if not needed.
    // Returns the SHA-1 hash of a String as a String.
    public static String sha1(String data) throws NoSuchAlgorithmException {

        byte[] hashBytes = MessageDigest.getInstance("SHA-1").digest(data.getBytes());
        return StringUtils.encodeHexString(hashBytes);

    }

    // Returns the opposite of isEmpty.
    public static boolean isNotEmpty(final CharSequence cs) {
        return !isEmpty(cs);
    }
    
    /**
     * isEmpty was copied from Apache commons-lang.StringUtils.
     * It's used in the capilize methods.
     * https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java
     * 
     * See the license below:
     * Licensed to the Apache Software Foundation (ASF) under one or more
     * contributor license agreements.  See the NOTICE file distributed with
     * this work for additional information regarding copyright ownership.
     * The ASF licenses this file to You under the Apache License, Version 2.0
     * (the "License"); you may not use this file except in compliance with
     * the License.  You may obtain a copy of the License at
     *
     *      http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     */

    /**
     * <p>Checks if a CharSequence is empty ("") or null.</p>
     *
     * <pre>
     * StringUtils.isEmpty(null)      = true
     * StringUtils.isEmpty("")        = true
     * StringUtils.isEmpty(" ")       = false
     * StringUtils.isEmpty("bob")     = false
     * StringUtils.isEmpty("  bob  ") = false
     * </pre>
     *
     * <p>NOTE: This method changed in Lang version 2.0.
     * It no longer trims the CharSequence.
     * That functionality is available in isBlank().</p>
     *
     * @param cs  the CharSequence to check, may be null
     * @return {@code true} if the CharSequence is empty or null
     * @since 3.0 Changed signature from isEmpty(String) to isEmpty(CharSequence)
     */
    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }

    /**
     * encodeHex and encodeHexString were copied from the Apache commons-codec
     * library.
     * https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Hex.java
     *
     */
    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_LOWER = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f'
    };

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_UPPER = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
        'E', 'F'
    };

    /**
     * Converts an array of bytes into a String representing the hexadecimal
     * values of each byte in order. The returned String will be double the
     * length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A String containing lower-case hexadecimal characters
     * @since 1.4
     */
    public static String encodeHexString(final byte[] data) {
        return new String(encodeHex(data));
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal
     * values of each byte in order. The returned String will be double the
     * length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data        a byte[] to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to
     * uppercase
     * @return A String containing lower-case hexadecimal characters
     * @since 1.11
     */
    public static String encodeHexString(final byte[] data, final boolean toLowerCase) {
        return new String(encodeHex(data, toLowerCase));
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be
     * double the length of the passed array, as it takes two characters to
     * represent any given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     */
    public static char[] encodeHex(final byte[] data) {
        return encodeHex(data, true);
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be
     * double the length of the passed array, as it takes two characters to
     * represent any given byte.
     *
     * @param data        a byte[] to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to
     * uppercase
     * @return A char[] containing hexadecimal characters in the selected case
     * @since 1.4
     */
    public static char[] encodeHex(final byte[] data, final boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be
     * double the length of the passed array, as it takes two characters to
     * represent any given byte.
     *
     * @param data     a byte[] to convert to Hex characters
     * @param toDigits the output alphabet (must contain at least 16 chars)
     * @return A char[] containing the appropriate characters from the alphabet
     *         For best results, this should be either upper- or lower-case hex.
     * @since 1.4
     */
    private static char[] encodeHex(final byte[] data, final char[] toDigits) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
    }
}