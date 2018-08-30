package com.tersesystems.proxyjsse.builder;

import com.tersesystems.proxyjsse.keystore.TrustStore;
import org.slieb.throwables.SupplierWithThrowable;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.*;
import java.security.cert.CertPathParameters;
import java.util.function.Supplier;

public class TrustManagerBuilder {

    private TrustManagerBuilder() {}

    public interface BuilderFinal {
        X509ExtendedTrustManager build() throws Exception;
    }

    public interface TrustManagerFactoryStage {

        ParametersStage withAlgorithm(String algorithm);

        ParametersStage withAlgorithmAndProvider(String algorithm, String provider);

        ParametersStage withDefaultAlgorithm();
    }

    static class TrustManagerFactoryStageImpl implements TrustManagerFactoryStage
    {
        @Override
        public ParametersStage withAlgorithm(String algorithm) {
            return new ParametersStageImpl(() -> TrustManagerFactory.getInstance(algorithm));
        }

        @Override
        public ParametersStage withAlgorithmAndProvider(String algorithm, String provider) {
            return new ParametersStageImpl(() -> TrustManagerFactory.getInstance(algorithm, provider));
        }

        @Override
        public ParametersStage withDefaultAlgorithm() {
            return new ParametersStageImpl(() -> TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()));
        }
    }

    public interface ParametersStage {
        BuilderFinal withKeyStore(KeyStore keyStore);
        BuilderFinal withKeyStore(SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier);

        BuilderFinal withTrustStore(TrustStore trustStore);
        BuilderFinal withTrustStore(Supplier<TrustStore> trustStore);

        BuilderFinal withDefaultKeystore();

        BuilderFinal withCertPathParameters(CertPathParameters parameters);
        BuilderFinal withCertPathParameters(SupplierWithThrowable<CertPathParameters, Exception> params);
    }

    static class ParametersStageImpl implements ParametersStage {

        private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> trustManagerFactory;

        ParametersStageImpl(SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> trustManagerFactory) {
            this.trustManagerFactory = trustManagerFactory;
        }

        @Override
        public BuilderFinal withKeyStore(KeyStore keyStore) {
            return new BuilderFinalKeyStoreImpl(trustManagerFactory, () -> keyStore);
        }

        @Override
        public BuilderFinal withKeyStore(SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier) {
            return new BuilderFinalKeyStoreImpl(trustManagerFactory, keyStoreSupplier);
        }

        @Override
        public BuilderFinal withTrustStore(TrustStore trustStore) {
            return new BuilderFinalKeyStoreImpl(trustManagerFactory, trustStore::keyStore);
        }

        @Override
        public BuilderFinal withTrustStore(Supplier<TrustStore> trustStore) {
            return new BuilderFinalKeyStoreImpl(trustManagerFactory, () -> trustStore.get().keyStore());
        }

        @Override
        public BuilderFinal withCertPathParameters(CertPathParameters params) {
            return new BuilderFinalParametersImpl(trustManagerFactory, () -> params);
        }

        @Override
        public BuilderFinal withCertPathParameters(SupplierWithThrowable<CertPathParameters, Exception> params) {
            return new BuilderFinalParametersImpl(trustManagerFactory, params);
        }

        @Override
        public BuilderFinal withDefaultKeystore() {
            return new BuilderFinalKeyStoreImpl(trustManagerFactory, () -> KeyStoreBuilder.defaultTrustManagerStore().build());
        }
    }

    static class BuilderFinalKeyStoreImpl implements BuilderFinal {
        private final SupplierWithThrowable<KeyStore, Exception> keyStore;
        private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> trustManagerFactory;

        BuilderFinalKeyStoreImpl(SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> tmf, SupplierWithThrowable<KeyStore, Exception> keyStore) {
            this.trustManagerFactory = tmf;
            this.keyStore = keyStore;
        }

        public X509ExtendedTrustManager build() throws Exception {
            TrustManagerFactory tmf = trustManagerFactory.getWithThrowable();
            tmf.init(keyStore.getWithThrowable());
            return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
        }
    }

    // FIXME SunX509 trust manager does not use trust manager parameters
    // FIXME only PKIX uses CertPathTrustManagerParameters
    static class BuilderFinalParametersImpl implements BuilderFinal {
        private final SupplierWithThrowable<CertPathParameters, Exception> parameters;
        private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> trustManagerFactory;

        BuilderFinalParametersImpl(SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> tmf, SupplierWithThrowable<CertPathParameters, Exception> parameters) {
            this.trustManagerFactory = tmf;
            this.parameters = parameters;
        }

        @Override
        public X509ExtendedTrustManager build() throws Exception {
            TrustManagerFactory tmf = trustManagerFactory.getWithThrowable();
            tmf.init(new CertPathTrustManagerParameters(parameters.getWithThrowable()));
            return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
        }
    }

    public static TrustManagerFactoryStage builder() {
        return new TrustManagerFactoryStageImpl();
    }

}
