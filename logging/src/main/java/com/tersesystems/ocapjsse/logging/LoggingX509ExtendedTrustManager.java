package com.tersesystems.ocapjsse.logging;

import com.tersesystems.ocapjsse.ProxyX509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

public class LoggingX509ExtendedTrustManager extends ProxyX509ExtendedTrustManager {

  private final TraceLogger tracer;

  public LoggingX509ExtendedTrustManager(
      final Supplier<X509ExtendedTrustManager> supplier, final TraceLogger tracer) {
    super(supplier);
    this.tracer = tracer;
  }

  public static Function<TrustManager, LoggingX509ExtendedTrustManager> transform(
      final TraceLogger tracer) {
    return (TrustManager tm) ->
        new LoggingX509ExtendedTrustManager(() -> (X509ExtendedTrustManager) tm, tracer);
  }

  @Override
  public void checkClientTrusted(
      final X509Certificate[] chain, final String authType, final Socket socket)
      throws CertificateException {
    final Object[] params = {chain, authType, socket};
    tracer.apply(
        "checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType, socket));
  }

  @Override
  public void checkServerTrusted(
      final X509Certificate[] chain, final String authType, final Socket socket)
      throws CertificateException {
    final Object[] params = {chain, authType, socket};
    tracer.apply(
        "checkServerTrusted", params, () -> super.checkServerTrusted(chain, authType, socket));
  }

  @Override
  public void checkClientTrusted(
      final X509Certificate[] chain, final String authType, final SSLEngine engine)
      throws CertificateException {
    final Object[] params = {chain, authType, engine};
    tracer.apply(
        "checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType, engine));
  }

  @Override
  public void checkServerTrusted(
      final X509Certificate[] chain, final String authType, final SSLEngine engine)
      throws CertificateException {
    final Object[] params = {chain, authType, engine};
    tracer.apply(
        "checkServerTrusted", params, () -> super.checkServerTrusted(chain, authType, engine));
  }

  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType)
      throws CertificateException {
    final Object[] params = {chain, authType};
    tracer.apply("checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType));
  }

  @Override
  public void checkServerTrusted(final X509Certificate[] chain, final String authType)
      throws CertificateException {
    final Object[] params = {chain, authType};
    tracer.apply("checkServerTrusted", params, () -> super.checkServerTrusted(chain, authType));
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    final Object[] params = {};
    return tracer.apply("getAcceptedIssuers", params, super::getAcceptedIssuers);
  }
}
