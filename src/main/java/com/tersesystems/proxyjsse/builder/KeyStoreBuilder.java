package com.tersesystems.proxyjsse.builder;

import org.slieb.throwables.SupplierWithThrowable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class KeyStoreBuilder {

    private KeyStoreBuilder() {}

    public interface KeyStoreStage {

        ParametersStage withDefaultType();

        ParametersStage withType(String type);

        DomainParametersStage withDomainType();

        ParametersStage withTypeAndProvider(String type, String provider);
    }

    static class KeyStoreStageImpl implements KeyStoreStage {

        @Override
        public ParametersStage withDefaultType() {
            return withType(KeyStore.getDefaultType());
        }

        @Override
        public ParametersStage withType(String type) {
            return new ParametersStageImpl(() -> KeyStore.getInstance(type));
        }

        @Override
        public DomainParametersStage withDomainType() {
            return new DomainParametersStageImpl(() -> KeyStore.getInstance("DKS"));
        }

        @Override
        public ParametersStage withTypeAndProvider(String type, String provider) {
            return new ParametersStageImpl(() -> KeyStore.getInstance(type, provider));
        }
    }

    public interface ParametersStage {
        PasswordStage withInputStream(InputStream inputStream);

        PasswordStage withPath(Path path);
    }

    static class ParametersStageImpl implements ParametersStage {
        private final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier;

        ParametersStageImpl(SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier) {
            this.supplier = supplier;
        }

        @Override
        public PasswordStage withInputStream(InputStream inputStream) {
            return new PasswordStageImpl(supplier, () -> inputStream);
        }

        @Override
        public PasswordStage withPath(Path path) {
            return new PasswordStageImpl(supplier, () -> new FileInputStream(path.toFile()));
        }
    }

    public interface DomainParametersStage {
        BuilderFinal withURIAndPasswordMap(URI uri, Map<String,KeyStore.ProtectionParameter> passwordMap);
    }

    static class DomainParametersStageImpl implements DomainParametersStage {
        private final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier;

        DomainParametersStageImpl(SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier) {
            this.supplier = supplier;
        }

        @Override
        public BuilderFinal withURIAndPasswordMap(URI uri, Map<String,KeyStore.ProtectionParameter> passwordMap) {
            return new BuilderFinalImpl(() -> {
                KeyStore keyStore = supplier.getWithThrowable();
                keyStore.load(new DomainLoadStoreParameter(uri, passwordMap));
                return keyStore;
            });
        }
    }

    public interface PasswordStage {
        BuilderFinal withPassword(char[] password);
    }

    static class PasswordStageImpl implements PasswordStage {
        private final SupplierWithThrowable<KeyStore, GeneralSecurityException> keyStore;
        private final SupplierWithThrowable<InputStream, Exception> inputStream;

        PasswordStageImpl(SupplierWithThrowable<KeyStore, GeneralSecurityException> keyStore, SupplierWithThrowable<InputStream, Exception> inputStream) {
            this.keyStore = keyStore;
            this.inputStream = inputStream;
        }

        @Override
        public BuilderFinal withPassword(char[] password) {
            return new BuilderFinalImpl(() -> {
                KeyStore keyStore = this.keyStore.getWithThrowable();
                keyStore.load(inputStream.getWithThrowable(), password);
                return keyStore;
            });
        }

    }

    public interface BuilderFinal {
        KeyStore build() throws Exception;
    }

    static class BuilderFinalImpl implements BuilderFinal {
        private final SupplierWithThrowable<KeyStore, Exception> supplier;

        BuilderFinalImpl(SupplierWithThrowable<KeyStore, Exception> supplier) {
            this.supplier = supplier;
        }

        @Override
        public KeyStore build() throws Exception {
            return supplier.getWithThrowable();
        }
    }

    public static KeyStoreStage builder() {
        return new KeyStoreStageImpl();
    }

    public static BuilderFinal empty() {
        return new BuilderFinalImpl(() -> {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            return keyStore;
        });
    }

    public static BuilderFinal empty(String type) {
        return new BuilderFinalImpl(() -> {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(null);
            return keyStore;
        });
    }

    public static BuilderFinal empty(String type, String provider) {
        return new BuilderFinalImpl(() -> {
            KeyStore keyStore = KeyStore.getInstance(type, provider);
            keyStore.load(null);
            return keyStore;
        });
    }

    public static BuilderFinal defaultKeyManagerStore() {
        return new BuilderFinalImpl(KeyStoreBuilder::getKeyManagerKeyStore);
    }

    public static BuilderFinal defaultTrustManagerStore() {
        return new BuilderFinalImpl(KeyStoreBuilder::getCacertsKeyStore);
    }

    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#CustomizingStores
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#T6
    //If the javax.net.ssl.keyStoreType and/or javax.net.ssl.keyStorePassword system properties are also specified,
    //then they are treated as the default KeyManager keystore type and password, respectively.
    //If no type is specified, then the default type is that returned by the KeyStore.getDefaultType() method,
    // which is the value of the keystore.type security property, or "jks" if no such security property is specified.
    //If no keystore password is specified, then it is assumed to be a blank string "".
    // From sun.security.ssl.SSLContextImpl
    private static KeyStore getKeyManagerKeyStore() throws Exception {
        final String NONE = "NONE";

        final Map<String,String> props = new HashMap<>();
        AccessController.doPrivileged(
                new PrivilegedExceptionAction<Object>() {
                    @Override
                    public Object run() throws Exception {
                        props.put("keyStore",  System.getProperty(
                                "javax.net.ssl.keyStore", ""));
                        props.put("keyStoreType", System.getProperty(
                                "javax.net.ssl.keyStoreType",
                                KeyStore.getDefaultType()));
                        props.put("keyStoreProvider", System.getProperty(
                                "javax.net.ssl.keyStoreProvider", ""));
                        props.put("keyStorePasswd", System.getProperty(
                                "javax.net.ssl.keyStorePassword", ""));
                        return null;
                    }
                });

        final String defaultKeyStore = props.get("keyStore");
        String defaultKeyStoreType = props.get("keyStoreType");
        String defaultKeyStoreProvider = props.get("keyStoreProvider");

        FileInputStream fs = null;
        KeyStore ks = null;
        char[] passwd = null;
        try {
            if (defaultKeyStore.length() != 0 &&
                    !NONE.equals(defaultKeyStore)) {
                fs = AccessController.doPrivileged(
                        new PrivilegedExceptionAction<FileInputStream>() {
                            @Override
                            public FileInputStream run() throws Exception {
                                return new FileInputStream(defaultKeyStore);
                            }
                        });
            }

            String defaultKeyStorePassword = props.get("keyStorePasswd");
            if (defaultKeyStorePassword.length() != 0) {
                passwd = defaultKeyStorePassword.toCharArray();
            }

            /**
             * Try to initialize key store.
             */
            if ((defaultKeyStoreType.length()) != 0) {
                if (defaultKeyStoreProvider.length() == 0) {
                    ks = KeyStore.getInstance(defaultKeyStoreType);
                } else {
                    ks = KeyStore.getInstance(defaultKeyStoreType,
                            defaultKeyStoreProvider);
                }

                // if defaultKeyStore is NONE, fs will be null
                ks.load(fs, passwd);
            }

            return ks;
        } finally {
            if (fs != null) {
                fs.close();
                fs = null;
            }
        }
    }

    // From sun.security.ssl.TrustManagerFactoryImpl
    private static KeyStore getCacertsKeyStore() throws Exception
    {
        String storeFileName = null;
        File storeFile = null;
        FileInputStream fis = null;
        String defaultTrustStoreType;
        String defaultTrustStoreProvider;
        final HashMap<String,String> props = new HashMap<>();
        final String sep = File.separator;
        KeyStore ks = null;

        AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                props.put("trustStore", System.getProperty(
                        "javax.net.ssl.trustStore"));
                props.put("javaHome", System.getProperty(
                        "java.home"));
                props.put("trustStoreType", System.getProperty(
                        "javax.net.ssl.trustStoreType",
                        KeyStore.getDefaultType()));
                props.put("trustStoreProvider", System.getProperty(
                        "javax.net.ssl.trustStoreProvider", ""));
                props.put("trustStorePasswd", System.getProperty(
                        "javax.net.ssl.trustStorePassword", ""));
                return null;
            }
        });

        /*
         * Try:
         *      javax.net.ssl.trustStore  (if this variable exists, stop)
         *      jssecacerts
         *      cacerts
         *
         * If none exists, we use an empty keystore.
         */

        try {
            storeFileName = props.get("trustStore");
            if (!"NONE".equals(storeFileName)) {
                if (storeFileName != null) {
                    storeFile = new File(storeFileName);
                    fis = getFileInputStream(storeFile);
                } else {
                    String javaHome = props.get("javaHome");
                    storeFile = new File(javaHome + sep + "lib" + sep
                            + "security" + sep +
                            "jssecacerts");
                    if ((fis = getFileInputStream(storeFile)) == null) {
                        storeFile = new File(javaHome + sep + "lib" + sep
                                + "security" + sep +
                                "cacerts");
                        fis = getFileInputStream(storeFile);
                    }
                }

                if (fis != null) {
                    storeFileName = storeFile.getPath();
                } else {
                    storeFileName = "No File Available, using empty keystore.";
                }
            }

            defaultTrustStoreType = props.get("trustStoreType");
            defaultTrustStoreProvider = props.get("trustStoreProvider");

            /*
             * Try to initialize trust store.
             */
            if (defaultTrustStoreType.length() != 0) {
                if (defaultTrustStoreProvider.length() == 0) {
                    ks = KeyStore.getInstance(defaultTrustStoreType);
                } else {
                    ks = KeyStore.getInstance(defaultTrustStoreType,
                            defaultTrustStoreProvider);
                }
                char[] passwd = null;
                String defaultTrustStorePassword =
                        props.get("trustStorePasswd");
                if (defaultTrustStorePassword.length() != 0)
                    passwd = defaultTrustStorePassword.toCharArray();

                // if trustStore is NONE, fis will be null
                ks.load(fis, passwd);

                // Zero out the temporary password storage
                if (passwd != null) {
                    for (int i = 0; i < passwd.length; i++) {
                        passwd[i] = (char)0;
                    }
                }
            }
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        return ks;
    }

    /*
     * Try to get an InputStream based on the file we pass in.
     */
    private static FileInputStream getFileInputStream(final File file)
            throws Exception {
        return AccessController.doPrivileged(
                new PrivilegedExceptionAction<FileInputStream>() {
                    @Override
                    public FileInputStream run() throws Exception {
                        try {
                            if (file.exists()) {
                                return new FileInputStream(file);
                            } else {
                                return null;
                            }
                        } catch (FileNotFoundException e) {
                            // couldn't find it, oh well.
                            return null;
                        }
                    }
                });
    }

}
