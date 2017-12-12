package eu.erasmuswithoutpaper.rsaaes;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import org.apache.commons.io.IOUtils;

/**
 * A common base for all other test classes. Provides some useful shortcut methods.
 */
public class TestBase {

  /**
   * Quick way of fetching files from resources.
   *
   * @param path A path relative to "test-files" directory. The file must exist.
   * @return The contents of the file.
   */
  protected static byte[] getFile(String path) {
    try {
      return getPossiblyNonExistingFile(path);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Same as {@link #getFile(String)}, but converts the file to String.
   *
   * @param path as in {@link #getFile(String)}.
   * @return Contents transformed to a string (with UTF-8 encoding).
   */
  protected static String getFileAsString(String path) {
    byte[] bytes = getFile(path);
    try {
      return new String(bytes, "utf-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Same as {@link #getFile(String)}, but the file is not required to exist.
   *
   * @param path as in {@link #getFile(String)}.
   * @throws IOException if the file does not exist.
   */
  protected static byte[] getPossiblyNonExistingFile(String path) throws IOException {
    InputStream stream = TestBase.class.getResourceAsStream("/test-files/" + path);
    if (stream == null) {
      throw new IOException("No such resource");
    }
    return IOUtils.toByteArray(stream);
  }
}
