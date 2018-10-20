package com.tersesystems.ocapjsse.revocable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tersesystems.ocapjsse.ProxyX509ExtendedKeyManager;
import com.tersesystems.securitybuilder.KeyManagerBuilder;
import com.tersesystems.securitybuilder.KeyPairCreator;
import com.tersesystems.securitybuilder.PrivateKeyStore;
import com.tersesystems.securitybuilder.RSAKeyPair;
import com.tersesystems.securitybuilder.X509CertificateCreator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import javax.net.ssl.X509ExtendedKeyManager;
import org.junit.jupiter.api.Test;

public class RevocableKeyManagerTest {

  @Test
  public void testKeyManager() throws Exception {
    X509ExtendedKeyManager keyManager = createKeyManager();
    assertThat(keyManager).isNotNull();

    Caretaker<X509ExtendedKeyManager> caretaker = Caretaker
        .create(keyManager, ProxyX509ExtendedKeyManager::new);
    X509ExtendedKeyManager proxyKeyManager = caretaker.getCapability();

    X509Certificate[] chain = proxyKeyManager.getCertificateChain("tersesystems.com");
    assertThat(chain).isNotNull();
    caretaker.getRevoker().revoke();

    Throwable throwable = catchThrowable(
        () -> proxyKeyManager.getCertificateChain("tersesystems.com"));
    assertThat(throwable).isInstanceOf(RevokedException.class);
  }

  private X509ExtendedKeyManager createKeyManager() throws Exception {
    KeyPairCreator.FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA()
        .withKeySize(2048);
    RSAKeyPair rootKeyPair = keyPairCreator.create();
    RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    RSAKeyPair eePair = keyPairCreator.create();

    X509CertificateCreator.IssuerStage<RSAPrivateKey> creator =
        X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";
    X509Certificate[] chain =
        creator
            .withRootCA(issuer, rootKeyPair, 2)
            .chain(
                rootKeyPair.getPrivate(),
                rootCreator ->
                    rootCreator
                        .withPublicKey(intermediateKeyPair.getPublic())
                        .withSubject("OU=intermediate CA")
                        .withCertificateAuthorityExtensions(0)
                        .chain(
                            intermediateKeyPair.getPrivate(),
                            intCreator ->
                                intCreator
                                    .withPublicKey(eePair.getPublic())
                                    .withSubject("CN=tersesystems.com")
                                    .withEndEntityExtensions()
                                    .chain()))
            .create();

    return KeyManagerBuilder.builder().withSunX509()
        .withPrivateKeyStore(PrivateKeyStore.create("tersesystems.com", eePair.getPrivate(), chain))
        .build();
  }

}
