package com.tersesystems.proxyjsse.builder;

import com.tersesystems.proxyjsse.keystore.PrivateKeyStore;
import org.slieb.throwables.SupplierWithThrowable;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.List;
import java.util.function.Supplier;

public class KeyManagerBuilder {
    private KeyManagerBuilder() {
    }

    public interface KeyManagerFactoryStage {
        SunParametersStage withSunX509();

        SunParametersStage withSunX509(String provider);

        NewSunParametersStage withNewSunX509();

        NewSunParametersStage withNewSunX509(String provider);
    }

    static class KeyManagerFactoryStageImpl implements KeyManagerFactoryStage
    {
        @Override
        public SunParametersStage withSunX509() {
            return new SunParametersStageImpl();
        }

        @Override
        public SunParametersStage withSunX509(String provider) {
            return new SunParametersStageImpl(provider);
        }

        @Override
        public NewSunParametersStage withNewSunX509() {
            return new NewSunParametersStageImpl();
        }

        @Override
        public NewSunParametersStage withNewSunX509(String provider) {
            return new NewSunParametersStageImpl(provider);
        }
    }


    public interface SunPasswordStage {
        BuilderFinal withPassword(char[] password);

        /**
         * Uses the password defined in the system property `javax.net.ssl.keyStorePassword`.
         */
        BuilderFinal withDefaultPassword();
    }

    static class SunPasswordStageImpl implements SunPasswordStage {

        private final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException> keyManagerFactory;
        private final Supplier<KeyStore> keyStore;

        SunPasswordStageImpl(SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException> keyManagerFactory, Supplier<KeyStore> keyStore) {
            this.keyManagerFactory = keyManagerFactory;
            this.keyStore = keyStore;
        }

        @Override
        public BuilderFinal withPassword(char[] password) {
            return new BuilderFinalImpl(() -> {
                KeyManagerFactory keyManagerFactory = this.keyManagerFactory.get();
                KeyStore keyStore = this.keyStore.get();
                keyManagerFactory.init(keyStore, password);
                return keyManagerFactory;
            });
        }

        public BuilderFinal withDefaultPassword() {
            return new BuilderFinalImpl(() -> {
                KeyManagerFactory keyManagerFactory = this.keyManagerFactory.get();
                KeyStore keyStore = this.keyStore.get();
                keyManagerFactory.init(keyStore, System.getProperty("javax.net.ssl.keyStorePassword", "").toCharArray());
                return keyManagerFactory;
            });
        }
    }

    public interface SunParametersStage {
        SunPasswordStage withKeyStore(KeyStore keyStore);
        SunPasswordStage withKeyStore(SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier);

        SunPasswordStage withPrivateKeyStore(PrivateKeyStore privateKeyStore);
        SunPasswordStage withPrivateKeyStore(Supplier<PrivateKeyStore> privateKeyStore);

        SunPasswordStage withDefaultKeyStore();
    }

    static class SunParametersStageImpl implements SunParametersStage {
        private static final String sunX509 = "SunX509";
        private String provider = null;

        SunParametersStageImpl() {
        }

        SunParametersStageImpl(String provider) {
            this.provider = provider;
        }

        @Override
        public SunPasswordStage withKeyStore(KeyStore keyStore) {
            return withKeyStore(() -> keyStore);
        }

        @Override
        public SunPasswordStage withKeyStore(SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier) {
            return new SunPasswordStageImpl(() -> {
                if (provider == null) {
                    return KeyManagerFactory.getInstance(sunX509);
                } else {
                    return KeyManagerFactory.getInstance(sunX509, provider);
                }
            }, keyStoreSupplier);
        }

        @Override
        public SunPasswordStage withPrivateKeyStore(PrivateKeyStore privateKeyStore) {
            return withPrivateKeyStore(() -> privateKeyStore);
        }

        @Override
        public SunPasswordStage withPrivateKeyStore(Supplier<PrivateKeyStore> privateKeyStore) {
            return withKeyStore(() -> privateKeyStore.get().keyStore());
        }

        @Override
        public SunPasswordStage withDefaultKeyStore() {
            return withKeyStore(() -> KeyStoreBuilder.defaultKeyManagerStore().build());
        }
    }

    public interface NewSunParametersStage {
        BuilderFinal withKeyStore(KeyStore keyStore, char[] password);
        BuilderFinal withKeyStore(KeyStore keyStore);

        BuilderFinal withBuilders(List<KeyStore.Builder> builders);
        BuilderFinal withBuilders(Supplier<List<KeyStore.Builder>> builders);

        // Technically there should be a NewSunPasswordStage, but under what circumstance
        // are you going to do that?
        BuilderFinal withDefaultKeyStoreAndPassword();
    }

    static class NewSunParametersStageImpl implements NewSunParametersStage {
        private static final String newSunX509 = "NewSunX509";
        private String provider = null;

        NewSunParametersStageImpl() {
        }

        NewSunParametersStageImpl(String provider) {
            this.provider = provider;
        }

        @Override
        public BuilderFinal withKeyStore(KeyStore keyStore) {
            return withKeyStore(keyStore, null);
        }

        @Override
        public BuilderFinal withKeyStore(KeyStore keyStore, char[] keyStorePassword) {
            return withBuilders(() -> KeyStoreBuildersBuilder.builder().withKeyStore(keyStore, keyStorePassword).build());
        }

        @Override
        public BuilderFinal withBuilders(List<KeyStore.Builder> builders) {
            return withBuilders(() -> builders);
        }

        @Override
        public BuilderFinal withBuilders(Supplier<List<KeyStore.Builder>> builders) {
            return new BuilderFinalImpl(() -> {
                KeyManagerFactory kmf = (provider == null) ? KeyManagerFactory.getInstance(newSunX509) : KeyManagerFactory.getInstance(newSunX509, provider);
                kmf.init(new KeyStoreBuilderParameters(builders.get()));
                return kmf;
            });
        }

        @Override
        public BuilderFinal withDefaultKeyStoreAndPassword() {
            return new BuilderFinalImpl(() -> {
                KeyManagerFactory kmf = (provider == null) ? KeyManagerFactory.getInstance(newSunX509) : KeyManagerFactory.getInstance(newSunX509, provider);
                KeyStore keyStore;
                try {
                    keyStore = KeyStoreBuilder.defaultKeyManagerStore().build();
                } catch (Exception e) {
                    // XXX FIXME either move this or fix it
                    throw new IllegalStateException(e);
                }
                kmf.init(keyStore, System.getProperty("javax.net.ssl.keyStorePassword", "").toCharArray());
                return kmf;
            });
        }
    }

    public interface BuilderFinal {
        X509ExtendedKeyManager build() throws GeneralSecurityException;
    }

    static class BuilderFinalImpl implements BuilderFinal {

        private final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException> keyManagerFactory;

        BuilderFinalImpl(SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException> keyManagerFactory) {
            this.keyManagerFactory = keyManagerFactory;
        }

        @Override
        public X509ExtendedKeyManager build() throws GeneralSecurityException {
            return (X509ExtendedKeyManager) keyManagerFactory.getWithThrowable().getKeyManagers()[0];
        }
    }

    public static KeyManagerFactoryStage builder() {
        return new KeyManagerFactoryStageImpl();
    }
}
