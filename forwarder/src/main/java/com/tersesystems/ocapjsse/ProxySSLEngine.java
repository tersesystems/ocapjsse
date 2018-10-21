package com.tersesystems.ocapjsse;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

public class ProxySSLEngine extends SSLEngine {

  protected final Supplier<SSLEngine> supplier;

  public ProxySSLEngine(final SSLEngine engine) {
    Objects.requireNonNull(engine);
    this.supplier = () -> engine;
  }

  public ProxySSLEngine(final Supplier<SSLEngine> supplier) {
    Objects.requireNonNull(supplier);
    this.supplier = supplier;
  }

  @Override
  public String getPeerHost() {
    return supplier.get().getPeerHost();
  }

  @Override
  public int getPeerPort() {
    return supplier.get().getPeerPort();
  }

  @Override
  public SSLEngineResult wrap(final ByteBuffer src, final ByteBuffer dst) throws SSLException {
    return supplier.get().wrap(src, dst);
  }

  @Override
  public SSLEngineResult wrap(final ByteBuffer[] srcs, final ByteBuffer dst) throws SSLException {
    return supplier.get().wrap(srcs, dst);
  }

  @Override
  public SSLEngineResult wrap(
      final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst)
      throws SSLException {
    return supplier.get().wrap(srcs, offset, length, dst);
  }

  @Override
  public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer dst) throws SSLException {
    return supplier.get().unwrap(src, dst);
  }

  @Override
  public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts) throws SSLException {
    return supplier.get().unwrap(src, dsts);
  }

  @Override
  public SSLEngineResult unwrap(
      final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length)
      throws SSLException {
    return supplier.get().unwrap(src, dsts, offset, length);
  }

  @Override
  public Runnable getDelegatedTask() {
    return supplier.get().getDelegatedTask();
  }

  @Override
  public void closeInbound() throws SSLException {
    supplier.get().closeInbound();
  }

  @Override
  public boolean isInboundDone() {
    return supplier.get().isInboundDone();
  }

  @Override
  public void closeOutbound() {
    supplier.get().closeOutbound();
  }

  @Override
  public boolean isOutboundDone() {
    return supplier.get().isOutboundDone();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return supplier.get().getSupportedCipherSuites();
  }

  @Override
  public String[] getEnabledCipherSuites() {
    return supplier.get().getEnabledCipherSuites();
  }

  @Override
  public void setEnabledCipherSuites(final String[] suites) {
    supplier.get().setEnabledCipherSuites(suites);
  }

  @Override
  public String[] getSupportedProtocols() {
    return supplier.get().getSupportedProtocols();
  }

  @Override
  public String[] getEnabledProtocols() {
    return supplier.get().getEnabledProtocols();
  }

  @Override
  public void setEnabledProtocols(final String[] protocols) {
    supplier.get().setEnabledProtocols(protocols);
  }

  @Override
  public SSLSession getSession() {
    return supplier.get().getSession();
  }

  @Override
  public SSLSession getHandshakeSession() {
    return supplier.get().getHandshakeSession();
  }

  @Override
  public void beginHandshake() throws SSLException {
    supplier.get().beginHandshake();
  }

  @Override
  public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
    return supplier.get().getHandshakeStatus();
  }

  @Override
  public boolean getUseClientMode() {
    return supplier.get().getUseClientMode();
  }

  @Override
  public void setUseClientMode(final boolean mode) {
    supplier.get().setUseClientMode(mode);
  }

  @Override
  public boolean getNeedClientAuth() {
    return supplier.get().getNeedClientAuth();
  }

  @Override
  public void setNeedClientAuth(final boolean need) {
    supplier.get().setNeedClientAuth(need);
  }

  @Override
  public boolean getWantClientAuth() {
    return supplier.get().getWantClientAuth();
  }

  @Override
  public void setWantClientAuth(final boolean want) {
    supplier.get().setWantClientAuth(want);
  }

  @Override
  public boolean getEnableSessionCreation() {
    return supplier.get().getEnableSessionCreation();
  }

  @Override
  public void setEnableSessionCreation(final boolean flag) {
    supplier.get().setEnableSessionCreation(flag);
  }

  @Override
  public SSLParameters getSSLParameters() {
    return supplier.get().getSSLParameters();
  }

  @Override
  public void setSSLParameters(final SSLParameters params) {
    supplier.get().setSSLParameters(params);
  }
}
