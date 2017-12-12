package eu.erasmuswithoutpaper.rsaaes;

/**
 * Thrown when the ewpRsaAesBody provided for decoding doesn't seem to be valid.
 */
public class BadEwpRsaAesBody extends Exception {

  private static final long serialVersionUID = 1L;

  public BadEwpRsaAesBody(Exception cause) {
    super(cause);
  }

}
