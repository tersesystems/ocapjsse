package com.tersesystems.proxyjsse.proxy;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public abstract class ProxyX509ExtendedKeyManager extends X509ExtendedKeyManager {

  protected Supplier<X509ExtendedKeyManager> supplier;

  public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
    return supplier.get().chooseEngineClientAlias(keyTypes, issuers, engine);
  }

  public String chooseEngineServerAlias(String keyTypes, Principal[] issuers, SSLEngine engine) {
    return supplier.get().chooseEngineServerAlias(keyTypes, issuers, engine);
  }

  @Override
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return supplier.get().getClientAliases(keyType, issuers);
  }

  @Override
  public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
    return supplier.get().chooseClientAlias(keyTypes, issuers, socket);
  }

  @Override
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    return supplier.get().getServerAliases(keyType, issuers);
  }

  @Override
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    return supplier.get().chooseServerAlias(keyType, issuers, socket);
  }

  @Override
  public X509Certificate[] getCertificateChain(String alias) {
    return supplier.get().getCertificateChain(alias);
  }

  @Override
  public PrivateKey getPrivateKey(String alias) {
    return supplier.get().getPrivateKey(alias);
  }
}
