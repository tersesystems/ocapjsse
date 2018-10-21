package com.tersesystems.proxyjsse.proxy;

import java.nio.ByteBuffer;
import java.util.function.Supplier;
import javax.net.ssl.*;

public class ProxySSLEngine extends SSLEngine {

  protected final Supplier<SSLEngine> delegate;

  public ProxySSLEngine(Supplier<SSLEngine> delegate) {
    this.delegate = delegate;
  }

  @Override
  public String getPeerHost() {
    return delegate.get().getPeerHost();
  }

  @Override
  public int getPeerPort() {
    return delegate.get().getPeerPort();
  }

  @Override
  public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
    return delegate.get().wrap(src, dst);
  }

  @Override
  public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
    return delegate.get().wrap(srcs, dst);
  }

  @Override
  public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
      throws SSLException {
    return delegate.get().wrap(srcs, offset, length, dst);
  }

  @Override
  public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
    return delegate.get().unwrap(src, dst);
  }

  @Override
  public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
    return delegate.get().unwrap(src, dsts);
  }

  @Override
  public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
      throws SSLException {
    return delegate.get().unwrap(src, dsts, offset, length);
  }

  @Override
  public Runnable getDelegatedTask() {
    return delegate.get().getDelegatedTask();
  }

  @Override
  public void closeInbound() throws SSLException {
    delegate.get().closeInbound();
  }

  @Override
  public boolean isInboundDone() {
    return delegate.get().isInboundDone();
  }

  @Override
  public void closeOutbound() {
    delegate.get().closeOutbound();
  }

  @Override
  public boolean isOutboundDone() {
    return delegate.get().isOutboundDone();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return delegate.get().getSupportedCipherSuites();
  }

  @Override
  public String[] getEnabledCipherSuites() {
    return delegate.get().getEnabledCipherSuites();
  }

  @Override
  public void setEnabledCipherSuites(String[] suites) {
    delegate.get().setEnabledCipherSuites(suites);
  }

  @Override
  public String[] getSupportedProtocols() {
    return delegate.get().getSupportedProtocols();
  }

  @Override
  public String[] getEnabledProtocols() {
    return delegate.get().getEnabledProtocols();
  }

  @Override
  public void setEnabledProtocols(String[] protocols) {
    delegate.get().setEnabledProtocols(protocols);
  }

  @Override
  public SSLSession getSession() {
    return delegate.get().getSession();
  }

  @Override
  public SSLSession getHandshakeSession() {
    return delegate.get().getHandshakeSession();
  }

  @Override
  public void beginHandshake() throws SSLException {
    delegate.get().beginHandshake();
  }

  @Override
  public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
    return delegate.get().getHandshakeStatus();
  }

  @Override
  public void setUseClientMode(boolean mode) {
    delegate.get().setUseClientMode(mode);
  }

  @Override
  public boolean getUseClientMode() {
    return delegate.get().getUseClientMode();
  }

  @Override
  public void setNeedClientAuth(boolean need) {
    delegate.get().setNeedClientAuth(need);
  }

  @Override
  public boolean getNeedClientAuth() {
    return delegate.get().getNeedClientAuth();
  }

  @Override
  public void setWantClientAuth(boolean want) {
    delegate.get().setWantClientAuth(want);
  }

  @Override
  public boolean getWantClientAuth() {
    return delegate.get().getWantClientAuth();
  }

  @Override
  public void setEnableSessionCreation(boolean flag) {
    delegate.get().setEnableSessionCreation(flag);
  }

  @Override
  public boolean getEnableSessionCreation() {
    return delegate.get().getEnableSessionCreation();
  }

  @Override
  public SSLParameters getSSLParameters() {
    return delegate.get().getSSLParameters();
  }

  @Override
  public void setSSLParameters(SSLParameters params) {
    delegate.get().setSSLParameters(params);
  }
}
