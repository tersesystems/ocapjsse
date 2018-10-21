package com.tersesystems.proxyjsse.keystore;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.util.*;
import java.util.stream.Collectors;

/** A keystore containing trusted certificate entries. */
public class TrustStoreImpl implements TrustStore {

  private final KeyStore keyStore;

  public TrustStoreImpl(KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  @Override
  public KeyStore keyStore() {
    return keyStore;
  }

  @Override
  public int size() {
    try {
      return keyStore.size();
    } catch (KeyStoreException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public boolean isEmpty() {
    return size() == 0;
  }

  @Override
  public boolean containsKey(Object key) {
    try {
      return keyStore.containsAlias((String) key);
    } catch (KeyStoreException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public boolean containsValue(Object value) {
    if (value instanceof KeyStore.TrustedCertificateEntry) {
      KeyStore.TrustedCertificateEntry trustedCertificateEntry =
          (KeyStore.TrustedCertificateEntry) value;
      Certificate trustedCertificate = trustedCertificateEntry.getTrustedCertificate();
      try {
        return keyStore.getCertificateAlias(trustedCertificate) != null;
      } catch (KeyStoreException e) {
        throw new IllegalStateException(e);
      }
    }
    return false;
  }

  @Override
  public KeyStore.TrustedCertificateEntry get(Object key) {
    try {
      return (KeyStore.TrustedCertificateEntry) keyStore.getEntry((String) key, null);
    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public KeyStore.TrustedCertificateEntry put(String key, KeyStore.TrustedCertificateEntry value) {
    try {
      keyStore.setEntry(key, value, null);
      return value;
    } catch (KeyStoreException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public KeyStore.TrustedCertificateEntry remove(Object key) {
    if (key instanceof String) {
      String s = (String) key;
      try {
        KeyStore.Entry entry = keyStore.getEntry(s, null);
        keyStore.deleteEntry(s);
        return (KeyStore.TrustedCertificateEntry) entry;
      } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
        throw new IllegalStateException(e);
      }
    } else {
      return null;
    }
  }

  @Override
  public void putAll(Map<? extends String, ? extends KeyStore.TrustedCertificateEntry> m) {
    // XXX FIXME
  }

  @Override
  public void clear() {
    // XXX FIXME
  }

  @Override
  public Set<String> keySet() {
    try {
      return new HashSet<>(Collections.list(keyStore.aliases()));
    } catch (KeyStoreException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public Collection<KeyStore.TrustedCertificateEntry> values() {
    return keySet()
        .stream()
        .map(
            alias -> {
              try {
                return (KeyStore.TrustedCertificateEntry) keyStore.getEntry(alias, null);
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
            })
        .collect(Collectors.toList());
  }

  @Override
  public Set<Entry<String, KeyStore.TrustedCertificateEntry>> entrySet() {
    return keySet()
        .stream()
        .map(
            alias -> {
              try {
                return new TrustStoreEntry(alias);
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
            })
        .collect(Collectors.toSet());
  }

  class TrustStoreEntry implements Entry<String, KeyStore.TrustedCertificateEntry> {

    private final String alias;

    TrustStoreEntry(String alias) {
      this.alias = alias;
    }

    @Override
    public String getKey() {
      return alias;
    }

    @Override
    public KeyStore.TrustedCertificateEntry getValue() {
      try {
        return (KeyStore.TrustedCertificateEntry) keyStore.getEntry(alias, null);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }

    @Override
    public KeyStore.TrustedCertificateEntry setValue(KeyStore.TrustedCertificateEntry value) {
      try {
        keyStore.setEntry(alias, value, null);
        return value;
      } catch (KeyStoreException e) {
        throw new IllegalStateException(e);
      }
    }

    @Override
    public boolean equals(Object o) {
      return false; // XXX FIXME
    }

    @Override
    public int hashCode() {
      return 0; // XXX FIXME
    }
  };
}
