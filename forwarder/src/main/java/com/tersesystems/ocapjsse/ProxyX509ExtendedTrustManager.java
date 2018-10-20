package com.tersesystems.ocapjsse;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

public class ProxyX509ExtendedTrustManager extends X509ExtendedTrustManager {

  protected final Supplier<X509ExtendedTrustManager> supplier;

  public ProxyX509ExtendedTrustManager(final X509ExtendedTrustManager trustManager) {
    Objects.requireNonNull(trustManager);
    this.supplier = () -> trustManager;
  }

  public ProxyX509ExtendedTrustManager(final Supplier<X509ExtendedTrustManager> supplier) {
    Objects.requireNonNull(supplier);
    this.supplier = supplier;
  }

  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType,
      final Socket socket)
      throws CertificateException {
    supplier.get().checkClientTrusted(chain, authType, socket);
  }

  @Override
  public void checkServerTrusted(final X509Certificate[] chain, final String authType,
      final Socket socket)
      throws CertificateException {
    supplier.get().checkServerTrusted(chain, authType, socket);
  }

  @Override
  public void checkClientTrusted(
      final X509Certificate[] chain, final String authType, final SSLEngine sslEngine)
      throws CertificateException {
    supplier.get().checkClientTrusted(chain, authType, sslEngine);
  }

  @Override
  public void checkServerTrusted(
      final X509Certificate[] chain, final String authType, final SSLEngine sslEngine)
      throws CertificateException {
    supplier.get().checkServerTrusted(chain, authType, sslEngine);
  }

  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType)
      throws CertificateException {
    supplier.get().checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(final X509Certificate[] chain, final String authType)
      throws CertificateException {
    supplier.get().checkServerTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return supplier.get().getAcceptedIssuers();
  }
}
