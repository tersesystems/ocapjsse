package com.tersesystems.proxyjsse.keystore;

import java.security.*;
import java.util.*;

public class PrivateKeyStoreImpl implements PrivateKeyStore {
  private final KeyStore keyStore;
  private final char[] password;

  public PrivateKeyStoreImpl(KeyStore keyStore, char[] password) {
    // FIXME implement this
    this.keyStore = keyStore;
    this.password = password;
  }

  @Override
  public KeyStore keyStore() {
    return keyStore;
  }

  @Override
  public int size() {
    return 0;
  }

  @Override
  public boolean isEmpty() {
    return false;
  }

  @Override
  public boolean containsKey(Object key) {
    return false;
  }

  @Override
  public boolean containsValue(Object value) {
    return false;
  }

  @Override
  public KeyStore.PrivateKeyEntry get(Object key) {
    return null;
  }

  @Override
  public KeyStore.PrivateKeyEntry put(String key, KeyStore.PrivateKeyEntry value) {
    return null;
  }

  @Override
  public KeyStore.PrivateKeyEntry remove(Object key) {
    return null;
  }

  @Override
  public void putAll(Map<? extends String, ? extends KeyStore.PrivateKeyEntry> m) {}

  @Override
  public void clear() {}

  @Override
  public Set<String> keySet() {
    return null;
  }

  @Override
  public Collection<KeyStore.PrivateKeyEntry> values() {
    return null;
  }

  @Override
  public Set<Entry<String, KeyStore.PrivateKeyEntry>> entrySet() {
    return null;
  }
}
