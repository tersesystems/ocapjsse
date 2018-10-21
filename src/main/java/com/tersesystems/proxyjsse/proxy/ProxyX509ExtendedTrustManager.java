package com.tersesystems.proxyjsse.proxy;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

public abstract class ProxyX509ExtendedTrustManager extends X509ExtendedTrustManager {

  protected Supplier<X509ExtendedTrustManager> supplier;

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    supplier.get().checkClientTrusted(chain, authType, socket);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    supplier.get().checkServerTrusted(chain, authType, socket);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine)
      throws CertificateException {
    supplier.get().checkClientTrusted(chain, authType, sslEngine);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine)
      throws CertificateException {
    supplier.get().checkServerTrusted(chain, authType, sslEngine);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    supplier.get().checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    supplier.get().checkServerTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return supplier.get().getAcceptedIssuers();
  }
}
