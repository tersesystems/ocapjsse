package com.tersesystems.ocapjsse.revocable;

import java.util.NoSuchElementException;
import java.util.concurrent.CountDownLatch;
import java.util.function.Function;
import java.util.function.Supplier;

interface Revoker {

  Revoker REVOKED =
      new Revoker() {
        @Override
        public void revoke() {}

        @Override
        public boolean isRevoked() {
          return true;
        }
      };

  void revoke();

  boolean isRevoked();
}

public abstract class Caretaker<C> {

  public static Caretaker<Object> REVOKED =
      new Caretaker<Object>() {
        @Override
        public Revoker getRevoker() {
          return Revoker.REVOKED;
        }

        @Override
        public Supplier<Object> getCapability() {
          throw new NoSuchElementException("Revoked.get");
        }
      };

  public static <N> Caretaker<N> create(N capability, Function<Supplier<N>, N> proxyFunction) {
    return lazyCreate((Supplier<N>) () -> capability, proxyFunction);
  }

  public static <N> Caretaker<N> lazyCreate(
      Supplier<N> capability, Function<Supplier<N>, N> proxyFunction) {
    final LatchRevoker revoker = new LatchRevoker();
    final Supplier<N> proxy =
        () -> {
          if (revoker.isRevoked()) {
            throw new RevokedException("Capability revoked!");
          } else {
            return capability.get();
          }
        };

    return new Caretaker<N>() {
      private final Supplier<N> supplier = () -> proxyFunction.apply(proxy);

      @Override
      public Revoker getRevoker() {
        return revoker;
      }

      @Override
      public N getCapability() {
        return supplier.get();
      }
    };
  }

  public abstract Revoker getRevoker();

  public abstract C getCapability();
}

class LatchRevoker implements Revoker {

  private CountDownLatch latch = new CountDownLatch(1);

  @Override
  public void revoke() {
    latch.countDown();
  }

  @Override
  public boolean isRevoked() {
    return latch.getCount() == 0;
  }
}
