package eu.erasmuswithoutpaper.rsaaes;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Encoder for the `ewp-rsa-aes128gcm` encryption, as defined here:
 * https://github.com/erasmus-without-paper/ewp-specs-sec-rsa-aes128gcm
 *
 * <p>
 * This class in thread-safe.
 * </p>
 */
public class EwpRsaAes128GcmEncoder {

  protected final RSAPublicKey recipientPublicKey;
  protected final byte[] recipientPublicKeyId;
  protected final SecretKey aesKey;
  protected final byte[] aesKeyEncrypted;

  /**
   * Create a new encoder for a specified recipient. This encoder can be reused for this recipient
   * (and only for this recipient).
   *
   * @param recipientPublicKey the public key of the recipient. It will be used to encrypt the
   *        underlying AES key (which in turn will be used for the actual payload encryption).
   */
  public EwpRsaAes128GcmEncoder(RSAPublicKey recipientPublicKey) {
    this.recipientPublicKey = recipientPublicKey;
    this.recipientPublicKeyId = Utils.getBinarySha256Fingerprint(recipientPublicKey.getEncoded());
    this.aesKey = this.generateNewAesKey();
    this.aesKeyEncrypted = this.encryptAesKey(this.aesKey);
  }

  /**
   * Encrypt the given payload and return the encoded result.
   *
   * @param body Payload to be encrypted.
   * @return Encrypted payload encoded in the <code>ewpRsaAesBody</code> format.
   */
  public byte[] encode(byte[] body) {

    // ByteBuffer buf = this.allocateBuffer(body);

    int bufferSize = 0;

    // SHA-256 hash of the recipient's public key (in binary).

    bufferSize += 32;

    // Integer, the length of the encrypted symmetric key.

    bufferSize += 2;

    // The encrypted AES key.

    bufferSize += this.aesKeyEncrypted.length;

    // AES initialization vector

    byte[] iv = this.generateNewIv();
    bufferSize += this.getGcmIvSize();

    // The encrypted body

    byte[] encryptedBody;
    Cipher cipherAes;
    try {
      cipherAes = Cipher.getInstance("AES/GCM/NoPadding");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new MissingFeature(e);
    }
    GCMParameterSpec spec = new GCMParameterSpec(this.getGcmTagLength() * 8, iv);
    try {
      cipherAes.init(Cipher.ENCRYPT_MODE, this.aesKey, spec);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
    try {
      encryptedBody = cipherAes.doFinal(body);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new RuntimeException(e);
    }
    bufferSize += encryptedBody.length;

    // Glue everything together.

    ByteBuffer buf = ByteBuffer.allocate(bufferSize);
    buf.put(this.recipientPublicKeyId);
    buf.putShort((short) this.aesKeyEncrypted.length);
    buf.put(this.aesKeyEncrypted);
    buf.put(iv);
    buf.put(encryptedBody);
    return buf.array();
  }

  /**
   * @return The public key of the recipient for which this encoder instance encrypts payloads for.
   */
  public RSAPublicKey getRecipientPublicKey() {
    return this.recipientPublicKey;
  }

  /**
   * @return SHA-256 fingerprint of the recipient's public key.
   */
  public byte[] getRecipientPublicKeySha256() {
    return this.recipientPublicKeyId.clone();
  }

  /**
   * @return Same as {@link #getRecipientPublicKeySha256()}, but formatted in Base64.
   */
  public String getRecipientPublicKeySha256Base64() {
    return Utils.b64encode(this.recipientPublicKeyId);
  }

  /**
   * @return Same as {@link #getRecipientPublicKeySha256()}, but formatted in HEX.
   */
  public String getRecipientPublicKeySha256Hex() {
    return Utils.hexEncode(this.recipientPublicKeyId);
  }

  @Override
  public String toString() {
    return "EwpRsaAes128GcmEncoder[recipient=" + this.getRecipientPublicKeySha256Hex() + "]";
  }

  protected byte[] encryptAesKey(SecretKey aesKey) {
    Cipher cipher;
    try {
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new MissingFeature(e);
    }
    try {
      cipher.init(Cipher.ENCRYPT_MODE, this.recipientPublicKey);
    } catch (InvalidKeyException e) {
      throw new RuntimeException(e);
    }
    try {
      return cipher.doFinal(aesKey.getEncoded());
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  protected SecretKey generateNewAesKey() {
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(this.getAesKeySize());
      return keyGen.generateKey();
    } catch (NoSuchAlgorithmException e) {
      throw new MissingFeature(e);
    }
  }

  protected byte[] generateNewIv() {
    SecureRandom rnd = new SecureRandom();
    byte[] iv = new byte[this.getGcmIvSize()];
    rnd.nextBytes(iv);
    return iv;
  }

  protected int getAesKeySize() {
    return 128;
  }

  protected int getGcmIvSize() {
    return 12;
  }

  protected int getGcmTagLength() {
    return 16;
  }
}
