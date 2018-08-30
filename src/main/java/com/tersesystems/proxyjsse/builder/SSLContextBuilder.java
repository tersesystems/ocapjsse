package com.tersesystems.proxyjsse.builder;

import javax.net.ssl.*;
import java.security.*;
import java.util.function.Supplier;

public class SSLContextBuilder {
    private SSLContextBuilder() {}

    public interface BuildFinal {
        BuildFinal withProtocol(String protocol);
        BuildFinal withProvider(String provider);

        BuildFinal withTrustManager(TrustManager trustManager);
        BuildFinal withTrustManager(Supplier<TrustManager> trustManagerSupplier);

        BuildFinal withKeyManager(KeyManager keyManager);
        BuildFinal withKeyManager(Supplier<KeyManager> trustManagerSupplier);

        BuildFinal withSecureRandom(SecureRandom secureRandom);
        BuildFinal withSecureRandom(Supplier<SecureRandom> secureRandomSupplier);

        SSLContext build() throws GeneralSecurityException;
    }

    static class BuildFinalImpl implements BuildFinal {

        private String protocol = "TLS";
        private Supplier<TrustManager> trustManagerSupplier = () -> null;
        private Supplier<KeyManager> keyManagerSupplier = () -> null;
        private String provider = null;
        private Supplier<SecureRandom> secureRandomSupplier = () -> null;

        BuildFinalImpl() {
        }

        @Override
        public BuildFinal withProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        @Override
        public BuildFinal withProvider(String provider) {
            this.provider = provider;
            return this;
        }

        @Override
        public BuildFinal withTrustManager(TrustManager trustManager) {
            this.trustManagerSupplier = () -> trustManager;
            return this;
        }

        @Override
        public BuildFinal withTrustManager(Supplier<TrustManager> trustManagerSupplier) {
            this.trustManagerSupplier = trustManagerSupplier;
            return this;
        }

        @Override
        public BuildFinal withKeyManager(KeyManager keyManager) {
            this.keyManagerSupplier = () -> keyManager;
            return this;
        }

        @Override
        public BuildFinal withKeyManager(Supplier<KeyManager> keyManagerSupplier) {
            this.keyManagerSupplier = keyManagerSupplier;
            return this;
        }

        @Override
        public BuildFinal withSecureRandom(SecureRandom secureRandom) {
            this.secureRandomSupplier = () -> secureRandom;
            return this;
        }

        @Override
        public BuildFinal withSecureRandom(Supplier<SecureRandom> secureRandomSupplier) {
            this.secureRandomSupplier = secureRandomSupplier;
            return this;
        }

        public SSLContext build() throws GeneralSecurityException {
            SSLContext sslContext;
            if (provider != null) {
                sslContext = SSLContext.getInstance(protocol, provider);
            } else {
                sslContext = SSLContext.getInstance(protocol);
            }

            KeyManager km = keyManagerSupplier.get();
            KeyManager[] kms = (km == null) ? null :  new KeyManager[] { km };

            TrustManager tm = trustManagerSupplier.get();
            TrustManager[] tms = (tm == null) ? null :  new TrustManager[] { tm };

            sslContext.init(kms, tms, secureRandomSupplier.get());
            return sslContext;
        }
    }

    public static BuildFinal builder() {
        return new BuildFinalImpl();
    }

}
