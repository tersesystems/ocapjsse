package com.tersesystems.proxyjsse.logging;

import org.slf4j.Logger;
import org.slieb.throwables.RunnableWithThrowable;
import org.slieb.throwables.SupplierWithThrowable;

interface MethodTracer {
    <T, E extends Throwable> T apply(String methodName, Object[] params, SupplierWithThrowable<T, E> t) throws E;
    <E extends Throwable> void apply(String methodName, Object[] params, RunnableWithThrowable<E> t) throws E;
}

abstract class AbstractMethodTracer implements MethodTracer {

    @Override
    public <R, E extends Throwable> R apply(String methodName, Object[] params, SupplierWithThrowable<R, E> ts) throws E {
        entry(methodName, params);
        R result = ts.onException(e -> exception(e, methodName, params)).get();
        return exit(result, methodName, params);
    }

    @Override
    public <E extends Throwable> void apply(String methodName, Object[] params, RunnableWithThrowable<E> runnable) throws E {
        entry(methodName, params);
        runnable.onException(e -> exception(e, methodName, params)).run();
        exit(methodName, params);
    }

    protected abstract void entry(String methodName, Object... parameters);

    protected abstract <R> R exit(R result, String methodName, Object... parameters);

    protected abstract void exit(String methodName, Object... parameters);

    protected abstract void exception(Throwable e, String methodName, Object... parameters);
}

class SLF4JMethodTracer extends AbstractMethodTracer {

    private final Logger logger;

    public SLF4JMethodTracer(Logger logger) {
        this.logger = logger;
    }

    @Override
    protected void entry(String methodName, Object... parameters) {
        logger.debug("entry: " + methodName);
    }

    @Override
    protected <R> R exit(R result, String methodName, Object... parameters) {
        logger.debug("exit: " + methodName);
        return result;
    }

    @Override
    protected void exit(String methodName, Object... parameters) {
        logger.debug("exit: " + methodName);
    }

    @Override
    protected void exception(Throwable e, String methodName, Object... parameters) {
        logger.error("exception: " + methodName);
    }
}