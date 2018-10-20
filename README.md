# Object Capability (OCAP) Enabled JSSE

This is a small library that provides proxies for JSSE based classes such as `SSLEngine`, `KeyManager` and `TrustManager`, and provides facilities to decorate behavior with logging and revocation.

## Construction

Object capabilities are based around deferred execution and composition, so that instead of dealing with a direct object reference, you deal with a proxy that manages your access to the object.  

Proxies are very simple to set up.  You define a supplier, and then you delegate all access through resolving that supplier.  Here's an example of X509ExtendedKeyManager set up with a proxy:

```java
package com.tersesystems.ocapjsse;

public class ProxyX509ExtendedKeyManager extends X509ExtendedKeyManager {

  protected Supplier<X509ExtendedKeyManager> supplier;

  public ProxyX509ExtendedKeyManager(Supplier<X509ExtendedKeyManager> supplier) {
    Objects.requireNonNull(supplier);
    this.supplier = supplier;
  }

  public String chooseEngineClientAlias(
      final String[] keyTypes, final Principal[] issuers, final SSLEngine engine) {
    return supplier.get().chooseEngineClientAlias(keyTypes, issuers, engine);
  }
  
  // ...
}
```

### Logging

Once you have a proxy, you can then set up logging around the manager: 

```java
package com.tersesystems.ocapjsse.revocable;

public class LoggingX509ExtendedTrustManager extends ProxyX509ExtendedTrustManager {
  private final TraceLogger tracer;

  public LoggingX509ExtendedTrustManager(
      final Supplier<X509ExtendedTrustManager> supplier, final TraceLogger tracer) {
    super(supplier);
    this.tracer = tracer;
  }

  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType,
      final Socket socket)
      throws CertificateException {
    final Object[] params = {chain, authType, socket};
    tracer.apply(
        "checkClientTrusted", params, () -> super.checkClientTrusted(chain, authType, socket));
  }
  
  // ...
}
```

This is a lightweight alternative to using the [debugjsse provider](https://github.com/tersesystems/debugjsse), as you can restrict logging to only a single trust manager.

### Revocation

You can even use a caretaker to set up revocation.  This can be used to break off communication immediately when a security guarantee is violated, or to enforce a time limit on access.

```java
package com.tersesystems.ocapjsse.revocable;

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
}
```

For more about revocation, see [managing accessibility with revocation](https://wsargent.github.io/ocaps/guide/management.html#managing-accessibility-with-revocation).