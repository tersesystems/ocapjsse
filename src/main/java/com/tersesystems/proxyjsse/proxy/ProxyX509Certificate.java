package com.tersesystems.proxyjsse.proxy;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.function.Supplier;

public abstract class ProxyX509Certificate extends X509Certificate {
    protected final Supplier<X509Certificate> supplier;

    public ProxyX509Certificate(X509Certificate cert) {
        Objects.requireNonNull(cert);
        this.supplier = () -> cert;
    }
    
    public ProxyX509Certificate(Supplier<X509Certificate> supplier) {
        Objects.requireNonNull(supplier);
        this.supplier = supplier;
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        supplier.get().checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        supplier.get().checkValidity(date);
    }

    @Override
    public int getVersion() {
        return supplier.get().getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return supplier.get().getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return supplier.get().getIssuerDN();
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        return supplier.get().getIssuerX500Principal();
    }

    @Override
    public Principal getSubjectDN() {
        return supplier.get().getSubjectDN();
    }

    @Override
    public X500Principal getSubjectX500Principal() {
        return supplier.get().getSubjectX500Principal();
    }

    @Override
    public Date getNotBefore() {
        return supplier.get().getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return supplier.get().getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return supplier.get().getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return supplier.get().getSignature();
    }

    @Override
    public String getSigAlgName() {
        return supplier.get().getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return supplier.get().getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return supplier.get().getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return supplier.get().getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return supplier.get().getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return supplier.get().getKeyUsage();
    }

    @Override
    public List<String> getExtendedKeyUsage() throws CertificateParsingException {
        return supplier.get().getExtendedKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        return supplier.get().getBasicConstraints();
    }

    @Override
    public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
        return supplier.get().getSubjectAlternativeNames();
    }

    @Override
    public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
        return supplier.get().getIssuerAlternativeNames();
    }

    @Override
    public void verify(PublicKey key, Provider sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        supplier.get().verify(key, sigProvider);
    }

    @Override
    public boolean equals(Object other) {
        return supplier.get().equals(other);
    }

    @Override
    public int hashCode() {
        return supplier.get().hashCode();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return supplier.get().getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        supplier.get().verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        supplier.get().verify(key, sigProvider);
    }

    @Override
    public String toString() {
        return supplier.get().toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return supplier.get().getPublicKey();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return supplier.get().hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return supplier.get().getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return supplier.get().getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return supplier.get().getExtensionValue(oid);
    }

}
