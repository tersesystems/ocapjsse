package com.tersesystems.proxyjsse.keystore;

import java.security.KeyStore;
import java.util.*;

public interface TrustStore extends Map<String, KeyStore.TrustedCertificateEntry> {

    public static TrustStore apply(KeyStore keyStore) {
        return new TrustStoreImpl(keyStore);
    }

    KeyStore keyStore();
}
