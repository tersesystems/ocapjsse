package com.tersesystems.ocapjsse.logging;

import org.slieb.throwables.RunnableWithThrowable;
import org.slieb.throwables.SupplierWithThrowable;

public abstract class AbstractTraceLogger implements TraceLogger {

  @Override
  public <R, E extends Throwable> R apply(
      final String methodName, final Object[] params, final SupplierWithThrowable<R, E> ts)
      throws E {
    entry(methodName, params);
    final R result = ts.onException(e -> exception(e, methodName, params)).get();
    return exit(result, methodName, params);
  }

  @Override
  public <E extends Throwable> void apply(
      final String methodName, final Object[] params, final RunnableWithThrowable<E> runnable)
      throws E {
    entry(methodName, params);
    runnable.onException(e -> exception(e, methodName, params)).run();
    exit(methodName, params);
  }

  protected abstract void entry(String methodName, Object... parameters);

  protected abstract <R> R exit(R result, String methodName, Object... parameters);

  protected abstract void exit(String methodName, Object... parameters);

  protected abstract void exception(Throwable e, String methodName, Object... parameters);
}
