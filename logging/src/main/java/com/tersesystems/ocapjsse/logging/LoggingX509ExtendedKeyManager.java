package com.tersesystems.ocapjsse.logging;

import com.tersesystems.ocapjsse.ProxyX509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public class LoggingX509ExtendedKeyManager extends ProxyX509ExtendedKeyManager {

  private final TraceLogger tracer;

  public LoggingX509ExtendedKeyManager(
      final Supplier<X509ExtendedKeyManager> supplier, final TraceLogger tracer) {
    super(supplier);
    this.tracer = tracer;
  }

  public String chooseEngineClientAlias(
      final String[] keyTypes, final Principal[] issuers, final SSLEngine engine) {
    final Object[] params = {keyTypes, issuers, engine};
    return tracer.apply(
        "chooseEngineClientAlias",
        params,
        () -> super.chooseEngineClientAlias(keyTypes, issuers, engine));
  }

  public String chooseEngineServerAlias(
      final String keyTypes, final Principal[] issuers, final SSLEngine engine) {
    final Object[] params = {keyTypes, issuers, engine};
    return tracer.apply(
        "chooseEngineServerAlias",
        params,
        () -> super.chooseEngineServerAlias(keyTypes, issuers, engine));
  }

  @Override
  public String[] getClientAliases(final String keyType, final Principal[] issuers) {
    final Object[] params = {keyType, issuers};
    return tracer.apply("getClientAliases", params, () -> super.getClientAliases(keyType, issuers));
  }

  @Override
  public String chooseClientAlias(final String[] keyTypes, final Principal[] issuers,
      final Socket socket) {
    final Object[] params = {keyTypes, issuers, socket};
    return tracer.apply(
        "chooseClientAlias", params, () -> super.chooseClientAlias(keyTypes, issuers, socket));
  }

  @Override
  public String[] getServerAliases(final String keyType, final Principal[] issuers) {
    final Object[] params = {keyType, issuers};
    return tracer.apply("getServerAliases", params, () -> super.getServerAliases(keyType, issuers));
  }

  @Override
  public String chooseServerAlias(final String keyType, final Principal[] issuers,
      final Socket socket) {
    final Object[] params = {keyType, issuers, socket};
    return tracer.apply(
        "chooseServerAlias", params, () -> super.chooseServerAlias(keyType, issuers, socket));
  }

  @Override
  public X509Certificate[] getCertificateChain(final String alias) {
    final Object[] params = {alias};
    return tracer.apply("getCertificateChain", params, () -> super.getCertificateChain(alias));
  }

  @Override
  public PrivateKey getPrivateKey(final String alias) {
    final Object[] params = {alias};
    return tracer.apply("getPrivateKey", params, () -> super.getPrivateKey(alias));
  }
}
