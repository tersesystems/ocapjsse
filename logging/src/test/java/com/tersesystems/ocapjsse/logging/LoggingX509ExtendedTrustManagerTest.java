package com.tersesystems.ocapjsse.logging;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.stream.Collectors;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;

public class LoggingX509ExtendedTrustManagerTest {

  @Test
  public void testLog() throws Exception {
    final TraceLogger tracer =
        new AbstractTraceLogger() {
          @Override
          protected void entry(final String methodName, final Object... parameters) {
            System.out.println("entry: " + methodName);
          }

          @Override
          protected <R> R exit(final R result, final String methodName,
              final Object... parameters) {
            System.out.println("exit: " + methodName);
            return result;
          }

          @Override
          protected void exit(final String methodName, final Object... parameters) {
            System.out.println("exit: " + methodName);
          }

          @Override
          protected void exception(final Throwable e, final String methodName,
              final Object... parameters) {
            System.out.println("exception: " + methodName);
          }
        };

    try {
      final SSLContext sslContext = SSLContext.getInstance("TLS");
      final TrustManagerFactory tmf =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init((KeyStore) null);
      final TrustManager[] tms =
          Arrays.stream(tmf.getTrustManagers())
              .map(LoggingX509ExtendedTrustManager.transform(tracer))
              .toArray(TrustManager[]::new);

      sslContext.init(null, tms, null);
      final HttpsURLConnection urlConnection =
          (HttpsURLConnection) new URL("https://www.google.com").openConnection();
      urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());

      try (final BufferedReader in =
          new BufferedReader(new InputStreamReader(urlConnection.getInputStream()))) {
        final String result = in.lines().collect(Collectors.joining());
        System.out.println(result);
      }
    } catch (final Exception e) {
      e.printStackTrace();
    }
  }
}
