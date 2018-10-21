package com.tersesystems.proxyjsse.logging;

import com.tersesystems.proxyjsse.proxy.ProxyX509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

public class LoggingX509ExtendedTrustManager extends ProxyX509ExtendedTrustManager {

  private final MethodTracer tracer;

  public LoggingX509ExtendedTrustManager(
      Supplier<X509ExtendedTrustManager> supplier, MethodTracer tracer) {
    this.supplier = supplier;
    this.tracer = tracer;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    Object[] params = {chain, authType, socket};
    tracer.apply(
        "checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType, socket));
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    Object[] params = {chain, authType, socket};
    tracer.apply(
        "checkServerTrusted", params, () -> super.checkServerTrusted(chain, authType, socket));
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    Object[] params = {chain, authType, engine};
    tracer.apply(
        "checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType, engine));
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    Object[] params = {chain, authType, engine};
    tracer.apply(
        "checkServerTrusted", params, () -> super.checkServerTrusted(chain, authType, engine));
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    Object[] params = {chain, authType};
    tracer.apply("checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType));
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    Object[] params = {chain, authType};
    tracer.apply("checkServerTrusted", params, () -> super.checkServerTrusted(chain, authType));
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    Object[] params = {};
    return tracer.apply("getAcceptedIssuers", params, super::getAcceptedIssuers);
  }
}
