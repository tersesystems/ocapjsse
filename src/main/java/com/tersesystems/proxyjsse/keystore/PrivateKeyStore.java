package com.tersesystems.proxyjsse.keystore;

import java.security.KeyStore;
import java.util.Map;

/**
 * Sets up a private keystore that is set up the way that the default SunX509 keymanager
 * expects -- that is, all the private keys have the same password.
 *
 * For keystores that have all individual passwords, i.e. "NewSunX509" keymanager style,
 * we can't use the map interface as noted here.
 */
public interface PrivateKeyStore extends Map<String, KeyStore.PrivateKeyEntry> {

    public static PrivateKeyStore apply(KeyStore keyStore, char[] password) {
        return new PrivateKeyStoreImpl(keyStore, password);
    }

    public static PrivateKeyStore apply(KeyStore keyStore) {
        return new PrivateKeyStoreImpl(keyStore, "".toCharArray());
    }

    KeyStore keyStore();
}
