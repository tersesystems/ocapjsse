package com.tersesystems.ocapjsse.revocable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tersesystems.ocapjsse.ProxySSLEngine;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.Test;

public class RevocableSSLEngineTest {

  @Test
  public void testRevokedEngine() throws Exception {
    SSLEngine sslEngine = createSSLEngine();
    assertThat(sslEngine).isNotNull();

    Caretaker<SSLEngine> sslEngineCaretaker = Caretaker.create(sslEngine, ProxySSLEngine::new);
    SSLEngine proxySSLEngine = sslEngineCaretaker.getCapability();

    String[] protocols = proxySSLEngine.getEnabledProtocols();
    assertThat(protocols).isNotNull();
    sslEngineCaretaker.getRevoker().revoke();

    Throwable throwable = catchThrowable(proxySSLEngine::getEnabledProtocols);
    assertThat(throwable).isInstanceOf(RevokedException.class);
  }

  private SSLEngine createSSLEngine() throws Exception {
    return SSLContext.getDefault().createSSLEngine();
  }
}
