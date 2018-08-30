package com.tersesystems.proxyjsse.builder;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.KeySpec;

public class PrivateKeyBuilder {

    private PrivateKeyBuilder() {
    }

    // DiffieHellman
    // DSA
    // RSA
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyFactory
    public PrivateKey generateKey(KeySpec keySpec, String keyAlgorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
