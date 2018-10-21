package com.tersesystems.ocapjsse;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public class ProxyX509ExtendedKeyManager extends X509ExtendedKeyManager {

  protected Supplier<X509ExtendedKeyManager> supplier;

  public ProxyX509ExtendedKeyManager(X509ExtendedKeyManager keyManager) {
    Objects.requireNonNull(keyManager);
    this.supplier = () -> keyManager;
  }

  public ProxyX509ExtendedKeyManager(Supplier<X509ExtendedKeyManager> supplier) {
    Objects.requireNonNull(supplier);
    this.supplier = supplier;
  }

  public String chooseEngineClientAlias(
      final String[] keyTypes, final Principal[] issuers, final SSLEngine engine) {
    return supplier.get().chooseEngineClientAlias(keyTypes, issuers, engine);
  }

  public String chooseEngineServerAlias(
      final String keyTypes, final Principal[] issuers, final SSLEngine engine) {
    return supplier.get().chooseEngineServerAlias(keyTypes, issuers, engine);
  }

  @Override
  public String[] getClientAliases(final String keyType, final Principal[] issuers) {
    return supplier.get().getClientAliases(keyType, issuers);
  }

  @Override
  public String chooseClientAlias(
      final String[] keyTypes, final Principal[] issuers, final Socket socket) {
    return supplier.get().chooseClientAlias(keyTypes, issuers, socket);
  }

  @Override
  public String[] getServerAliases(final String keyType, final Principal[] issuers) {
    return supplier.get().getServerAliases(keyType, issuers);
  }

  @Override
  public String chooseServerAlias(
      final String keyType, final Principal[] issuers, final Socket socket) {
    return supplier.get().chooseServerAlias(keyType, issuers, socket);
  }

  @Override
  public X509Certificate[] getCertificateChain(final String alias) {
    return supplier.get().getCertificateChain(alias);
  }

  @Override
  public PrivateKey getPrivateKey(final String alias) {
    return supplier.get().getPrivateKey(alias);
  }
}
