package com.tersesystems.ocapjsse.revocable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tersesystems.ocapjsse.ProxyX509Certificate;
import com.tersesystems.securitybuilder.KeyPairCreator;
import com.tersesystems.securitybuilder.X509CertificateCreator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import org.junit.jupiter.api.Test;

public class RevocableX509CertificateTest {

  @Test
  public void testX509Certificate() throws Exception {
    X509Certificate certificate = createX509Certificate();
    assertThat(certificate).isNotNull();

    Caretaker<X509Certificate> caretaker = Caretaker.create(certificate, ProxyX509Certificate::new);
    X509Certificate proxyCertificate = caretaker.getCapability();

    Date notAfter = proxyCertificate.getNotAfter();
    assertThat(notAfter).isNotNull();
    caretaker.getRevoker().revoke();

    Throwable throwable = catchThrowable(proxyCertificate::getNotAfter);
    assertThat(throwable).isInstanceOf(RevokedException.class);
  }

  private X509Certificate createX509Certificate() throws Exception {
    String issuer = "CN=letsencrypt.derp,O=Root CA";
    return X509CertificateCreator.creator()
        .withSHA256withRSA()
        .withDuration(Duration.ofDays(365))
        .withRootCA(issuer, KeyPairCreator.creator().withRSA().withKeySize(2048).create(), 2)
        .create();
  }
}
