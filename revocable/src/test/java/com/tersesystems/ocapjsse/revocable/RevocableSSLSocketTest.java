package com.tersesystems.ocapjsse.revocable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tersesystems.ocapjsse.ProxySSLSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.junit.jupiter.api.Test;

public class RevocableSSLSocketTest {

  @Test
  public void testSSLSocket() throws Exception {
    SSLSocket sslSocket = createSSLSocket();
    assertThat(sslSocket).isNotNull();

    Caretaker<SSLSocket> caretaker = Caretaker.create(sslSocket, ProxySSLSocket::new);

    SSLSocket proxySSLSocket = caretaker.getCapability();
    boolean needClientAuth = proxySSLSocket.getNeedClientAuth();
    assertThat(needClientAuth).isFalse();

    caretaker.getRevoker().revoke();
    Throwable throwable = catchThrowable(() -> proxySSLSocket.getNeedClientAuth());
    assertThat(throwable).isInstanceOf(RevokedException.class);
  }

  private SSLSocket createSSLSocket() throws Exception {
    SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    return (SSLSocket) socketFactory.createSocket();
  }
}
