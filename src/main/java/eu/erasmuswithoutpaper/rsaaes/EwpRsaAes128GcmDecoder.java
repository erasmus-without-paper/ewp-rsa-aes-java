package eu.erasmuswithoutpaper.rsaaes;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Decoder for the `ewp-rsa-aes128gcm` encryption, as defined here:
 * https://github.com/erasmus-without-paper/ewp-specs-sec-rsa-aes128gcm
 *
 * <p>
 * This class in thread-safe.
 * </p>
 */
public class EwpRsaAes128GcmDecoder {

  /**
   * A set of both intermediate and final values used during the decryption process. This is usually
   * not needed for the caller, but can be used for debugging and unit-testing.
   */
  static class DecryptionInternals {
    byte[] recipientPublicKeySha256;
    int encryptedAesKeyLength;
    byte[] encryptedAesKey;
    byte[] aesKey;
    SecretKey aesKeyImpl;
    byte[] iv;
    int encryptedPayloadOffset;
    byte[] payload;
  }

  /**
   * Given the encrypted payload encoded in the <code>ewpRsaAesBody</code> format, extract the
   * SHA-256 fingerprint of the payload's recipient's public key. If multiple recipient keys are
   * used, then this method can be used to pick a proper keypair before
   * {@link EwpRsaAes128GcmDecoder} instance is instantiated.
   *
   * @param ewpRsaAesBody The encrypted payload, encoded in <code>ewpRsaAesBody</code> format.
   * @return 16-byte-long binary SHA-256 fingerprint of the payload's recipient's RSA public key.
   * @throws BadEwpRsaAesBody When ewpRsaAesBody doesn't seem to be valid.
   */
  public static byte[] extractRecipientPublicKeySha256(byte[] ewpRsaAesBody)
      throws BadEwpRsaAesBody {
    try {
      return Arrays.copyOf(ewpRsaAesBody, 32);
    } catch (BufferUnderflowException e) {
      throw new BadEwpRsaAesBody(e);
    }
  }

  /**
   * Same as {@link #extractRecipientPublicKeySha256(byte[])}, but the result is Base64-encoded.
   *
   * @param ewpRsaAesBody The encrypted payload, encoded in <code>ewpRsaAesBody</code> format.
   * @return Base64-encoded SHA-256 fingerprint of the payload's recipient's RSA public key.
   */
  public static String extractRecipientPublicKeySha256Base64(byte[] ewpRsaAesBody) {
    return Utils.b64encode(Arrays.copyOf(ewpRsaAesBody, 32));
  }

  /**
   * Same as {@link #extractRecipientPublicKeySha256(byte[])}, but the result is hex-encoded.
   *
   * @param ewpRsaAesBody The encrypted payload, encoded in <code>ewpRsaAesBody</code> format.
   * @return Hex-encoded SHA-256 fingerprint of the payload's recipient's RSA public key.
   */
  public static String extractRecipientPublicKeySha256Hex(byte[] ewpRsaAesBody) {
    return Utils.hexEncode(Arrays.copyOf(ewpRsaAesBody, 32));
  }

  protected final RSAPublicKey recipientPublicKey;
  protected final byte[] recipientPublicKeyId;
  protected final RSAPrivateKey recipientPrivateKey;
  protected final Map<ByteBuffer, SecretKey> aesKeysCache;

  /**
   * Create a new decoder for a specified recipient. This decoder can be reused for this recipient.
   *
   * @param recipientPublicKey The public key of the recipient.
   * @param recipientPrivateKey The private key of the recipient. It must match the public key.
   */
  public EwpRsaAes128GcmDecoder(RSAPublicKey recipientPublicKey,
      RSAPrivateKey recipientPrivateKey) {
    this.recipientPublicKey = recipientPublicKey;
    this.recipientPublicKeyId = Utils.getBinarySha256Fingerprint(recipientPublicKey.getEncoded());
    this.recipientPrivateKey = recipientPrivateKey;
    this.aesKeysCache = Collections
        .synchronizedMap(new LruCache<ByteBuffer, SecretKey>(this.getAesKeysCacheSize()));
  }

  /**
   * @param ewpRsaAesBody The encrypted payload, encoded in <code>ewpRsaAesBody</code> format.
   * @return True, if this decoder's recipient matches the desired recipient of the given encrypted
   *         payload.
   * @throws BadEwpRsaAesBody When ewpRsaAesBody doesn't seem to be valid.
   */
  public boolean canDecode(byte[] ewpRsaAesBody) throws BadEwpRsaAesBody {
    return Arrays.equals(this.recipientPublicKeyId, extractRecipientPublicKeySha256(ewpRsaAesBody));
  }

  /**
   * Decode the given <code>ewpRsaAesBody</code> content, decrypt it, and return the decrypted
   * payload.
   *
   * @param ewpRsaAesBody The encrypted payload, encoded in <code>ewpRsaAesBody</code> format.
   * @return The decrypted payload.
   * @throws BadEwpRsaAesBody When ewpRsaAesBody doesn't seem to be valid.
   * @throws InvalidRecipient When the payload's recipient doesn't match the recipient for which
   *         this decoder has been created for.
   */
  public byte[] decode(byte[] ewpRsaAesBody) throws BadEwpRsaAesBody, InvalidRecipient {
    return this.decodeWithDetails(ewpRsaAesBody).payload;
  }

  /**
   * @return The public key of the recipient for which this decoder instance decrypts payloads for.
   */
  public RSAPublicKey getRecipientPublicKey() {
    return this.recipientPublicKey;
  }

  /**
   * @return SHA-256 fingerprint of the recipient's public key (for which this decoder instance
   *         decrypts payloads for).
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
    return "EwpRsaAes128GcmDecoder[recipient=" + this.getRecipientPublicKeySha256Hex() + "]";
  }

  protected int getAesKeysCacheSize() {
    return 20;
  }

  protected int getGcmIvSize() {
    return 12;
  }

  protected int getGcmTagLength() {
    return 16;
  }

  DecryptionInternals decodeWithDetails(byte[] ewpRsaAesBody)
      throws BadEwpRsaAesBody, InvalidRecipient {

    DecryptionInternals vars = new DecryptionInternals();
    ByteBuffer buf = ByteBuffer.wrap(ewpRsaAesBody);

    try {

      // Check if the recipient matches.

      vars.recipientPublicKeySha256 = new byte[32];
      buf.get(vars.recipientPublicKeySha256);
      if (!Arrays.equals(this.recipientPublicKeyId, vars.recipientPublicKeySha256)) {
        throw new InvalidRecipient();
      }

      // Read the encrypted symmetric key.

      vars.encryptedAesKeyLength = buf.getShort() & 0xffff;
      vars.encryptedAesKey = new byte[vars.encryptedAesKeyLength];
      buf.get(vars.encryptedAesKey);

      // Check if we have this encryptedAesKey in our cache.

      ByteBuffer cacheKey = ByteBuffer.wrap(vars.encryptedAesKey);
      if (this.aesKeysCache.containsKey(cacheKey)) {
        vars.aesKeyImpl = this.aesKeysCache.get(cacheKey);
        vars.aesKey = vars.aesKeyImpl.getEncoded();
      } else {

        // Not found in our cache. Decrypt the key.

        Cipher cipherRsa;
        try {
          cipherRsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
          throw new MissingFeature(e);
        }
        try {
          cipherRsa.init(Cipher.DECRYPT_MODE, this.recipientPrivateKey);
        } catch (InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        try {
          vars.aesKey = cipherRsa.doFinal(vars.encryptedAesKey);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
          throw new BadEwpRsaAesBody(e);
        }
        vars.aesKeyImpl = new SecretKeySpec(vars.aesKey, 0, vars.aesKey.length, "AES");

        // Cache it.

        this.aesKeysCache.put(cacheKey, vars.aesKeyImpl);
      }

      // Read AES initialization vector.

      vars.iv = new byte[this.getGcmIvSize()];
      buf.get(vars.iv);

      // Decrypt the body.

      Cipher cipherAes;
      try {
        cipherAes = Cipher.getInstance("AES/GCM/NoPadding");
      } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
        throw new MissingFeature(e);
      }
      GCMParameterSpec spec = new GCMParameterSpec(this.getGcmTagLength() * 8, vars.iv);
      try {
        cipherAes.init(Cipher.DECRYPT_MODE, vars.aesKeyImpl, spec);
      } catch (InvalidAlgorithmParameterException e) {
        throw new RuntimeException(e);
      } catch (InvalidKeyException e) {
        throw new BadEwpRsaAesBody(e);
      }
      vars.encryptedPayloadOffset = buf.position();
      try {
        vars.payload = cipherAes.doFinal(ewpRsaAesBody, vars.encryptedPayloadOffset,
            ewpRsaAesBody.length - vars.encryptedPayloadOffset);
      } catch (IllegalBlockSizeException | BadPaddingException e) {
        throw new BadEwpRsaAesBody(e);
      }

      return vars;

    } catch (BufferUnderflowException e) {
      throw new BadEwpRsaAesBody(e);
    }
  }
}
