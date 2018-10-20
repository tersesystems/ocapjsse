package com.tersesystems.ocapjsse.logging;

import org.slf4j.Logger;

public class SLF4JTraceLogger extends AbstractTraceLogger {

  private final Logger logger;

  public SLF4JTraceLogger(final Logger logger) {
    this.logger = logger;
  }

  @Override
  protected void entry(final String methodName, final Object... parameters) {
    logger.debug("entry: " + methodName);
  }

  @Override
  protected <R> R exit(final R result, final String methodName, final Object... parameters) {
    logger.debug("exit: " + methodName);
    return result;
  }

  @Override
  protected void exit(final String methodName, final Object... parameters) {
    logger.debug("exit: " + methodName);
  }

  @Override
  protected void exception(final Throwable e, final String methodName, final Object... parameters) {
    logger.error("exception: " + methodName);
  }
}
