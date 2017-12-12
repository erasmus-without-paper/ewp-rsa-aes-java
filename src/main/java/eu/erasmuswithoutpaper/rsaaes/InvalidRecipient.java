package eu.erasmuswithoutpaper.rsaaes;

/**
 * Thrown when the declared recipient of the encrypted payload doesn't match the recipient for which
 * the decoder was constructed.
 */
public class InvalidRecipient extends Exception {
  private static final long serialVersionUID = 1L;
}
