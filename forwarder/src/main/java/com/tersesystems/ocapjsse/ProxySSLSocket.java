package com.tersesystems.ocapjsse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.Objects;
import java.util.function.Supplier;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class ProxySSLSocket extends SSLSocket {

  protected final Supplier<SSLSocket> supplier;

  public ProxySSLSocket(final SSLSocket socket) {
    Objects.requireNonNull(socket);
    this.supplier = () -> socket;
  }

  public ProxySSLSocket(final Supplier<SSLSocket> supplier) {
    Objects.requireNonNull(supplier);
    this.supplier = supplier;
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
  public void addHandshakeCompletedListener(final HandshakeCompletedListener listener) {
    supplier.get().addHandshakeCompletedListener(listener);
  }

  @Override
  public void removeHandshakeCompletedListener(final HandshakeCompletedListener listener) {
    supplier.get().removeHandshakeCompletedListener(listener);
  }

  @Override
  public void startHandshake() throws IOException {
    supplier.get().startHandshake();
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

  @Override
  public void connect(final SocketAddress endpoint) throws IOException {
    supplier.get().connect(endpoint);
  }

  @Override
  public void connect(final SocketAddress endpoint, final int timeout) throws IOException {
    supplier.get().connect(endpoint, timeout);
  }

  @Override
  public void bind(final SocketAddress bindpoint) throws IOException {
    supplier.get().bind(bindpoint);
  }

  @Override
  public InetAddress getInetAddress() {
    return supplier.get().getInetAddress();
  }

  @Override
  public InetAddress getLocalAddress() {
    return supplier.get().getLocalAddress();
  }

  @Override
  public int getPort() {
    return supplier.get().getPort();
  }

  @Override
  public int getLocalPort() {
    return supplier.get().getLocalPort();
  }

  @Override
  public SocketAddress getRemoteSocketAddress() {
    return supplier.get().getRemoteSocketAddress();
  }

  @Override
  public SocketAddress getLocalSocketAddress() {
    return supplier.get().getLocalSocketAddress();
  }

  @Override
  public SocketChannel getChannel() {
    return supplier.get().getChannel();
  }

  @Override
  public InputStream getInputStream() throws IOException {
    return supplier.get().getInputStream();
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    return supplier.get().getOutputStream();
  }

  @Override
  public boolean getTcpNoDelay() throws SocketException {
    return supplier.get().getTcpNoDelay();
  }

  @Override
  public void setTcpNoDelay(final boolean on) throws SocketException {
    supplier.get().setTcpNoDelay(on);
  }

  @Override
  public void setSoLinger(final boolean on, final int linger) throws SocketException {
    supplier.get().setSoLinger(on, linger);
  }

  @Override
  public int getSoLinger() throws SocketException {
    return supplier.get().getSoLinger();
  }

  @Override
  public void sendUrgentData(final int data) throws IOException {
    supplier.get().sendUrgentData(data);
  }

  @Override
  public boolean getOOBInline() throws SocketException {
    return supplier.get().getOOBInline();
  }

  @Override
  public void setOOBInline(final boolean on) throws SocketException {
    supplier.get().setOOBInline(on);
  }

  @Override
  public int getSoTimeout() throws SocketException {
    return supplier.get().getSoTimeout();
  }

  @Override
  public void setSoTimeout(final int timeout) throws SocketException {
    supplier.get().setSoTimeout(timeout);
  }

  @Override
  public int getSendBufferSize() throws SocketException {
    return supplier.get().getSendBufferSize();
  }

  @Override
  public void setSendBufferSize(final int size) throws SocketException {
    supplier.get().setSendBufferSize(size);
  }

  @Override
  public int getReceiveBufferSize() throws SocketException {
    return supplier.get().getReceiveBufferSize();
  }

  @Override
  public void setReceiveBufferSize(final int size) throws SocketException {
    supplier.get().setReceiveBufferSize(size);
  }

  @Override
  public boolean getKeepAlive() throws SocketException {
    return supplier.get().getKeepAlive();
  }

  @Override
  public void setKeepAlive(final boolean on) throws SocketException {
    supplier.get().setKeepAlive(on);
  }

  @Override
  public int getTrafficClass() throws SocketException {
    return supplier.get().getTrafficClass();
  }

  @Override
  public void setTrafficClass(final int tc) throws SocketException {
    supplier.get().setTrafficClass(tc);
  }

  @Override
  public boolean getReuseAddress() throws SocketException {
    return supplier.get().getReuseAddress();
  }

  @Override
  public void setReuseAddress(final boolean on) throws SocketException {
    supplier.get().setReuseAddress(on);
  }

  @Override
  public void close() throws IOException {
    supplier.get().close();
  }

  @Override
  public void shutdownInput() throws IOException {
    supplier.get().shutdownInput();
  }

  @Override
  public void shutdownOutput() throws IOException {
    supplier.get().shutdownOutput();
  }

  @Override
  public String toString() {
    return supplier.get().toString();
  }

  @Override
  public boolean isConnected() {
    return supplier.get().isConnected();
  }

  @Override
  public boolean isBound() {
    return supplier.get().isBound();
  }

  @Override
  public boolean isClosed() {
    return supplier.get().isClosed();
  }

  @Override
  public boolean isInputShutdown() {
    return supplier.get().isInputShutdown();
  }

  @Override
  public boolean isOutputShutdown() {
    return supplier.get().isOutputShutdown();
  }

  @Override
  public void setPerformancePreferences(final int connectionTime, final int latency,
      final int bandwidth) {
    supplier.get().setPerformancePreferences(connectionTime, latency, bandwidth);
  }
}
