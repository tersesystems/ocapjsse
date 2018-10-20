package com.tersesystems.ocapjsse.revocable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tersesystems.ocapjsse.ProxyX509ExtendedTrustManager;
import com.tersesystems.securitybuilder.TrustManagerBuilder;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.Test;

public class RevocableTrustManagerTest {

  @Test
  public void testRevokedEngine() throws Exception {
    X509ExtendedTrustManager trustManager = createTrustManager();
    assertThat(trustManager).isNotNull();

    Caretaker<X509ExtendedTrustManager> caretaker = Caretaker
        .create(trustManager, ProxyX509ExtendedTrustManager::new);
    X509ExtendedTrustManager proxyTrustManager = caretaker.getCapability();

    X509Certificate[] issuers = proxyTrustManager.getAcceptedIssuers();
    assertThat(issuers).isNotNull();
    caretaker.getRevoker().revoke();

    Throwable throwable = catchThrowable(proxyTrustManager::getAcceptedIssuers);
    assertThat(throwable).isInstanceOf(RevokedException.class);
  }

  private X509ExtendedTrustManager createTrustManager() throws Exception {
    return TrustManagerBuilder.builder().withDefaultAlgorithm().withDefaultKeystore().build();
  }
}
