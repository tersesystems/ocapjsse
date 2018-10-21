package com.tersesystems.proxyjsse.builder;

import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static javax.crypto.Cipher.DECRYPT_MODE;

import java.io.IOException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class KeySpecBuilder {

  // generates private key from PKCS8 encoding
  public PKCS8EncodedKeySpec generatePrivate(char[] keyPassword, String content) {
    try {

      // optional keyPassword
      Pattern KEY_PATTERN =
          Pattern.compile(
              "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+"
                  + // Header
                  "([a-z0-9+/=\\r\\n]+)"
                  + // Base64 text
                  "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+", // Footer
              CASE_INSENSITIVE);

      Matcher matcher = KEY_PATTERN.matcher(content);
      if (!matcher.find()) {
        throw new IOException("found no private key!");
      }
      byte[] encodedKey = java.util.Base64.getMimeDecoder().decode(matcher.group(1));
      if (keyPassword == null) {
        return new PKCS8EncodedKeySpec(encodedKey);
      }

      EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encodedKey);
      SecretKeyFactory keyFactory =
          SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
      SecretKey secretKey = keyFactory.generateSecret(new PBEKeySpec(keyPassword));

      Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
      cipher.init(DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());

      return encryptedPrivateKeyInfo.getKeySpec(cipher);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
