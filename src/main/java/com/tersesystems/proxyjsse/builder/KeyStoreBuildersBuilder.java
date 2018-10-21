package com.tersesystems.proxyjsse.builder;

import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class KeyStoreBuildersBuilder {

  private KeyStoreBuildersBuilder() {}

  public interface BuilderFinal {
    BuilderFinal withKeyStore(KeyStore keyStore, char[] password);

    BuilderFinal withProtectionParameter(
        String type, Provider provider, KeyStore.ProtectionParameter protectionParameter);

    BuilderFinal withProtectionParameter(
        String type, Provider provider, File file, KeyStore.ProtectionParameter protection);

    BuilderFinal withBuilders(KeyStore.Builder... builders);

    BuilderFinal withBuilders(List<KeyStore.Builder> builders);

    List<KeyStore.Builder> build();
  }

  static class BuilderFinalImpl implements BuilderFinal {

    private final List<KeyStore.Builder> builders;

    BuilderFinalImpl() {
      this.builders = new ArrayList<>();
    }

    @Override
    public BuilderFinal withKeyStore(KeyStore keyStore, char[] keyStorePassword) {
      KeyStore.Builder builder =
          KeyStore.Builder.newInstance(keyStore, new KeyStore.PasswordProtection(keyStorePassword));
      this.builders.add(builder);
      return this;
    }

    @Override
    public BuilderFinal withProtectionParameter(
        String type, Provider provider, KeyStore.ProtectionParameter protectionParameter) {
      KeyStore.Builder builder = KeyStore.Builder.newInstance(type, provider, protectionParameter);
      this.builders.add(builder);
      return this;
    }

    @Override
    public BuilderFinal withProtectionParameter(
        String type, Provider provider, File file, KeyStore.ProtectionParameter protection) {
      KeyStore.Builder builder = KeyStore.Builder.newInstance(type, provider, file, protection);
      this.builders.add(builder);
      return this;
    }

    @Override
    public BuilderFinal withBuilders(KeyStore.Builder... builders) {
      this.builders.addAll(Arrays.asList(builders));
      return this;
    }

    @Override
    public BuilderFinal withBuilders(List<KeyStore.Builder> builders) {
      this.builders.addAll(builders);
      return this;
    }

    @Override
    public List<KeyStore.Builder> build() {
      return this.builders;
    }
  }

  public static BuilderFinal builder() {
    return new BuilderFinalImpl();
  }
}
