package eu.erasmuswithoutpaper.rsaaes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.erasmuswithoutpaper.rsaaes.EwpRsaAes128GcmDecoder.DecryptionInternals;

public class EwpRsaAes128GcmTest extends TestBase {

  private static RSAPublicKey recipientPublicKey;
  private static RSAPrivateKey recipientPrivateKey;

  @BeforeClass
  public static void setUpClass() {
    try {
      KeyFactory kf = KeyFactory.getInstance("RSA");
      recipientPrivateKey = (RSAPrivateKey) kf.generatePrivate(
          new PKCS8EncodedKeySpec(Utils.b64decode(getFileAsString("rsa1-private"))));
      recipientPublicKey = (RSAPublicKey) kf
          .generatePublic(new X509EncodedKeySpec(Utils.b64decode(getFileAsString("rsa1-public"))));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void generateNewExampleForSpecWorks() throws BadEwpRsaAesBody, InvalidRecipient {
    String example = this.generateNewExampleForSpec();
    // assertThat(example).isEqualTo("Something");
  }

  @Test
  public void testBasicUsage() throws BadEwpRsaAesBody, InvalidRecipient {
    EwpRsaAes128GcmEncoder encoder = new EwpRsaAes128GcmEncoder(recipientPublicKey);
    byte[] payload = "This is a secret".getBytes(StandardCharsets.UTF_8);
    byte[] ewpRsaAesBody = encoder.encode(payload);

    EwpRsaAes128GcmDecoder decoder =
        new EwpRsaAes128GcmDecoder(recipientPublicKey, recipientPrivateKey);
    byte[] decryptedPayload = decoder.decode(ewpRsaAesBody);
    assertThat(decryptedPayload).isEqualTo(payload);
  }

  @Test
  public void testErrors() {

    EwpRsaAes128GcmDecoder decoder =
        new EwpRsaAes128GcmDecoder(recipientPublicKey, recipientPrivateKey);

    byte[] ewpRsaAesBody;

    /* Bytes near the end were changed. Should fail during GCM AuthTag checking. */

    ewpRsaAesBody = Utils.b64decode(getFileAsString("example1-ewpRsaAesBody-broken1"));
    try {
      decoder.decode(ewpRsaAesBody);
      fail("Exception expected, but not thrown");
    } catch (BadEwpRsaAesBody e) {
      // Expected.
    } catch (InvalidRecipient e) {
      throw new RuntimeException(e);
    }

    /*
     * Bytes in the RSA-encrypted section are changed. Should fail during RSA decryption, or AES key
     * construction.
     */

    ewpRsaAesBody = Utils.b64decode(getFileAsString("example1-ewpRsaAesBody-broken2"));
    try {
      decoder.decode(ewpRsaAesBody);
      fail("Exception expected, but not thrown");
    } catch (BadEwpRsaAesBody e) {
      // Expected.
    } catch (InvalidRecipient e) {
      throw new RuntimeException(e);
    }

    /* Bytes are appended to an otherwise valid body. Should fail during GCM AuthTag checking. */

    ewpRsaAesBody = Utils.b64decode(getFileAsString("example1-ewpRsaAesBody-appended"));
    try {
      decoder.decode(ewpRsaAesBody);
      fail("Exception expected, but not thrown");
    } catch (BadEwpRsaAesBody e) {
      // Expected.
    } catch (InvalidRecipient e) {
      throw new RuntimeException(e);
    }

    /*
     * Bytes are changed in the beginning, so that the recipient ID should not match the one used by
     * our decoder.
     */

    ewpRsaAesBody = Utils.b64decode(getFileAsString("example1-ewpRsaAesBody-badrecipient"));
    try {
      decoder.decode(ewpRsaAesBody);
      fail("Exception expected, but not thrown");
    } catch (BadEwpRsaAesBody e) {
      throw new RuntimeException(e);
    } catch (InvalidRecipient e) {
      // Expected.
    }

  }

  @Test
  public void testExampleFromSpec() throws BadEwpRsaAesBody, InvalidRecipient {
    byte[] ewpRsaAesBody = Utils.b64decode(getFileAsString("example1-ewpRsaAesBody"));

    EwpRsaAes128GcmDecoder decoder =
        new EwpRsaAes128GcmDecoder(recipientPublicKey, recipientPrivateKey);
    DecryptionInternals details = decoder.decodeWithDetails(ewpRsaAesBody);

    // recipientPublicKeyFingerprint

    assertThat(Utils.b64encode(details.recipientPublicKeySha256))
        .isEqualTo("A1ATd09ZbhiHNEvaigZGIDB1lZI1XbP1HISY/9Cxit0=");

    // aesKey

    assertThat(details.encryptedAesKeyLength).isEqualTo(256); // 2048 bits (size of the RSA key)
    assertThat(Utils.b64encode(details.encryptedAesKey))
        .isEqualTo(getFileAsString("example1-encryptedAesKey"));
    assertThat(details.aesKey.length).isEqualTo(16);
    assertThat(Utils.b64encode(details.aesKey)).isEqualTo("Gwaty5wYxuD81f++z6jwZw==");

    // iv

    assertThat(Utils.b64encode(details.iv)).isEqualTo("t8/I35bQAcG6YpXk");

    // encryptedPayload

    assertThat(details.encryptedPayloadOffset).isEqualTo(302);
    byte[] encryptedPayload =
        Arrays.copyOfRange(ewpRsaAesBody, details.encryptedPayloadOffset, ewpRsaAesBody.length);
    assertThat(Utils.b64encode(encryptedPayload))
        .isEqualTo("tIsU5R2OToxjUqI2V/vFyNAuArAkFVK4TLI0Tk5Vo5yN");

    // payload

    assertThat(details.payload.length).isEqualTo(17);
    assertThat(Utils.b64encode(details.payload)).isEqualTo("VGhpcyBpcyBhIHNlY3JldC4=");
    assertThat(new String(details.payload, StandardCharsets.UTF_8)).isEqualTo("This is a secret.");
  }

  private String generateNewExampleForSpec() throws BadEwpRsaAesBody, InvalidRecipient {

    StringBuilder sb = new StringBuilder();
    sb.append("// recipientPublicKey\n");
    sb.append(Utils.b64encode(recipientPublicKey.getEncoded())).append("\n\n");
    sb.append("// recipientPrivateKey\n");
    sb.append(Utils.b64encode(recipientPrivateKey.getEncoded())).append("\n\n");

    byte[] originalContent = "This is a secret.".getBytes(StandardCharsets.UTF_8);
    EwpRsaAes128GcmEncoder encoder = new EwpRsaAes128GcmEncoder(recipientPublicKey);
    byte[] ewpRsaAesBody = encoder.encode(originalContent);
    sb.append("// ewpRsaAesBody\n");
    sb.append(Utils.b64encode(ewpRsaAesBody)).append("\n\n");

    EwpRsaAes128GcmDecoder decoder =
        new EwpRsaAes128GcmDecoder(recipientPublicKey, recipientPrivateKey);
    DecryptionInternals details = decoder.decodeWithDetails(ewpRsaAesBody);
    sb.append("// recipientPublicKeyFingerprint (base64)\n");
    sb.append(Utils.b64encode(details.recipientPublicKeySha256)).append("\n\n");
    sb.append("// encryptedAesKeyLength\n");
    sb.append(details.encryptedAesKeyLength).append("\n\n");
    sb.append("// encryptedAesKey (base64)\n");
    sb.append(Utils.b64encode(details.encryptedAesKey)).append("\n\n");
    sb.append("// aesKey (base64)\n");
    sb.append(Utils.b64encode(details.aesKey)).append("\n\n");
    sb.append("// iv (base64)\n");
    sb.append(Utils.b64encode(details.iv)).append("\n\n");
    sb.append("// encryptedPayloadOffset\n");
    sb.append(details.encryptedPayloadOffset).append("\n\n");
    byte[] encryptedPayload =
        Arrays.copyOfRange(ewpRsaAesBody, details.encryptedPayloadOffset, ewpRsaAesBody.length);
    sb.append("// encryptedPayload (base64)\n");
    sb.append(Utils.b64encode(encryptedPayload)).append("\n\n");
    sb.append("// payload (base64)\n");
    sb.append(Utils.b64encode(details.payload)).append("\n\n");
    sb.append("// payload (UTF-8)\n");
    sb.append(new String(details.payload, StandardCharsets.UTF_8)).append("\n\n");

    String example = sb.toString();
    return example;
  }
}
