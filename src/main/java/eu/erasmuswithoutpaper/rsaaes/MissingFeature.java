package eu.erasmuswithoutpaper.rsaaes;

/**
 * Thrown when some of the security algorithms or features required by this library are not properly
 * registered (in general, this shouldn't happen in Java 8).
 */
public class MissingFeature extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public MissingFeature(Exception cause) {
    super(cause);
  }

}
