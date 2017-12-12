package eu.erasmuswithoutpaper.rsaaes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

class Utils {

  private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
  private static final byte[] LF = new byte[] { 0x0A };

  static String addLineBreaks(String str, int lineLength) {
    StringBuilder sb = new StringBuilder();
    int offset = 0;
    while (true) {
      int nextOffset = offset + lineLength;
      if (nextOffset < str.length()) {
        sb.append(str.substring(offset, nextOffset));
        sb.append('\n');
        offset = nextOffset;
      } else {
        sb.append(str.substring(offset));
        break;
      }
    }
    return sb.toString();
  }

  static byte[] b64decode(String encoded) {
    return Base64.getMimeDecoder().decode(encoded);
  }

  static String b64encode(byte[] data) {
    return Base64.getMimeEncoder(76, LF).encodeToString(data);
  }

  static byte[] getBinarySha256Fingerprint(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  static String hexEncode(byte[] data) {
    char[] chars = new char[2 * data.length];
    for (int i = 0; i < data.length; ++i) {
      chars[2 * i] = HEX_CHARS[(data[i] & 0xF0) >>> 4];
      chars[2 * i + 1] = HEX_CHARS[data[i] & 0x0F];
    }
    return new String(chars);
  }
}
