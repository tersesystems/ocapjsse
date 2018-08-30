package com.tersesystems.proxyjsse.logging;

import com.tersesystems.proxyjsse.builder.KeyManagerBuilder;
import com.tersesystems.proxyjsse.builder.KeyStoreBuilder;
import com.tersesystems.proxyjsse.builder.SSLContextBuilder;
import com.tersesystems.proxyjsse.builder.TrustManagerBuilder;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;

public class LoggingX509ExtendedTrustManagerTest
{
    @Test
    public void shouldAnswerWithTrue() throws Exception {
        MethodTracer tracer = new AbstractMethodTracer() {
            @Override
            protected void entry(String methodName, Object... parameters) {
                System.out.println("entry: " + methodName);
            }

            @Override
            protected <R> R exit(R result, String methodName, Object... parameters) {
                System.out.println("exit: " + methodName);
                return result;
            }

            @Override
            protected void exit(String methodName, Object... parameters) {
                System.out.println("exit: " + methodName);
            }

            @Override
            protected void exception(Throwable e, String methodName, Object... parameters) {
                System.out.println("exception: " + methodName);
            }
        };


        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            String filename = "derp.cer";
            FileInputStream fis = new FileInputStream(filename);
            Certificate[] certChain = certificateFactory.generateCertificates(fis).toArray(new Certificate[0]);

            //            KeyStore keyStore = KeyStoreBuilder.builder()
            //                    .withDomainType()
            //                    .withParameter(DomainLoadStoreParameterBuilder.builder().build())
            //                    .build();
            //KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, certChain);
            //privateKeyStoreMap.setEntry("derp", privateKeyEntry);

            X509ExtendedKeyManager km = KeyManagerBuilder.builder()
                    .withNewSunX509()
                    .withDefaultKeyStoreAndPassword()
                    .build();

            X509ExtendedTrustManager tm = TrustManagerBuilder.builder()
                    .withAlgorithm("PKIX")
                    .withCertPathParameters(new PKIXParameters(KeyStoreBuilder.empty().build()))
                    .build();

            SSLContext sslContext = SSLContextBuilder.builder()
                    .withKeyManager(km)
                    .withTrustManager(new LoggingX509ExtendedTrustManager(() -> tm, tracer))
                    .build();

            sslContext.createSSLEngine();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
