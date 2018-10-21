package com.tersesystems.proxyjsse.builder;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;

public class PublicKeyBuilder {

  public PublicKey generateKey(KeySpec keySpec, String keyAlgorithm) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
      return keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
