package com.tersesystems.proxyjsse.proxy;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.channels.SocketChannel;
import java.util.function.Supplier;

public class ProxySSLSocket extends SSLSocket {

    protected final Supplier<SSLSocket> delegate;

    public ProxySSLSocket(Supplier<SSLSocket> delegate) {
        this.delegate = delegate;
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
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.get().addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.get().removeHandshakeCompletedListener(listener);
    }

    @Override
    public void startHandshake() throws IOException {
        delegate.get().startHandshake();
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

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        delegate.get().connect(endpoint);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        delegate.get().connect(endpoint, timeout);
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        delegate.get().bind(bindpoint);
    }

    @Override
    public InetAddress getInetAddress() {
        return delegate.get().getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return delegate.get().getLocalAddress();
    }

    @Override
    public int getPort() {
        return delegate.get().getPort();
    }

    @Override
    public int getLocalPort() {
        return delegate.get().getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return delegate.get().getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return delegate.get().getLocalSocketAddress();
    }

    @Override
    public SocketChannel getChannel() {
        return delegate.get().getChannel();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return delegate.get().getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return delegate.get().getOutputStream();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        delegate.get().setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return delegate.get().getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        delegate.get().setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return delegate.get().getSoLinger();
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        delegate.get().sendUrgentData(data);
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        delegate.get().setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return delegate.get().getOOBInline();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        delegate.get().setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return delegate.get().getSoTimeout();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        delegate.get().setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return delegate.get().getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        delegate.get().setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return delegate.get().getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        delegate.get().setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return delegate.get().getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        delegate.get().setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return delegate.get().getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        delegate.get().setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return delegate.get().getReuseAddress();
    }

    @Override
    public void close() throws IOException {
        delegate.get().close();
    }

    @Override
    public void shutdownInput() throws IOException {
        delegate.get().shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException {
        delegate.get().shutdownOutput();
    }

    @Override
    public String toString() {
        return delegate.get().toString();
    }

    @Override
    public boolean isConnected() {
        return delegate.get().isConnected();
    }

    @Override
    public boolean isBound() {
        return delegate.get().isBound();
    }

    @Override
    public boolean isClosed() {
        return delegate.get().isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return delegate.get().isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return delegate.get().isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        delegate.get().setPerformancePreferences(connectionTime, latency, bandwidth);
    }

}
