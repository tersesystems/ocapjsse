package com.tersesystems.ocapjsse.logging;

import org.slieb.throwables.RunnableWithThrowable;
import org.slieb.throwables.SupplierWithThrowable;

public interface TraceLogger {

  <T, E extends Throwable> T apply(
      String methodName, Object[] params, SupplierWithThrowable<T, E> t) throws E;

  <E extends Throwable> void apply(String methodName, Object[] params, RunnableWithThrowable<E> t)
      throws E;
}
