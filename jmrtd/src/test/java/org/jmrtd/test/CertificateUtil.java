/*
 * $Id: $
 */

package org.jmrtd.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

/**
 * Certificate utilities for testing.
 * 
 * @author The JMRTD team (info@jmrtd.org)
 * 
 * @version $Revision: $
 */
public class CertificateUtil {
  
  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  /**
   * Prevents instantiation.
   */
  private CertificateUtil() {
  }
  
  /**
   * Generates a certificate.
   * 
   * @param issuer the issuer DN as a comma-separated list
   * @param subject the subject DN as a comma-separated list
   * @param dateOfIssuing the date of issuing
   * @param dateOfExpiry the date of expiry
   * @param subjecPublicKey the subject's public key
   * @param issuerPrivateKey the issuer's private key
   * @param signatureAlgorithm the signature algorithm to use in Java mnemonic notation
   * 
   * @return the generated certificate
   * 
   * @throws CertificateEncodingException on error
   * @throws InvalidKeyException on error
   * @throws IllegalStateException on error
   * @throws NoSuchProviderException on error
   * @throws NoSuchAlgorithmException on error
   * @throws SignatureException on error
   */
  public static X509Certificate createCertificate(String issuer, String subject, Date dateOfIssuing, Date dateOfExpiry,
      PublicKey subjectPublicKey, PrivateKey issuerPrivateKey, String signatureAlgorithm) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
    
    try {
      X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(new X500Name(issuer), new BigInteger("1"), dateOfIssuing, dateOfExpiry, new X500Name(subject), SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded()));
      byte[] certBytes = certBuilder.build(new JCESigner(issuerPrivateKey, signatureAlgorithm)).getEncoded();
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      return (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (Exception  e) {
      LOGGER.log(Level.SEVERE, "Unexpected exception", e);
      throw new IllegalStateException(e.getMessage());
    }
  }
  
  /**
   * A content signer implementation.
   */
  private static class JCESigner implements ContentSigner {
    
    private static final List<String> SUPPORTED_ALGORITHMS = Arrays.asList(new String[] { "SHA256withRSA", "SHA256withECDSA" });
    private static final AlgorithmIdentifier PKCS1_SHA256_WITH_RSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
    private static final AlgorithmIdentifier X9_SHA256_WITH_ECDSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
    
    private Signature signature;
    private ByteArrayOutputStream outputStream;
    
    public JCESigner(PrivateKey privateKey, String signatureAlgorithm) {
      if (!SUPPORTED_ALGORITHMS.contains(signatureAlgorithm)) {
        throw new IllegalArgumentException("Signature algorithm \"" + signatureAlgorithm + "\" not yet supported");
      }
      try {
        this.outputStream = new ByteArrayOutputStream();
        this.signature = Signature.getInstance(signatureAlgorithm);
        this.signature.initSign(privateKey);
      } catch (GeneralSecurityException gse) {
        throw new IllegalArgumentException(gse.getMessage());
      }
    }
    
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      if (signature.getAlgorithm().equals("SHA256withRSA")) {
        return PKCS1_SHA256_WITH_RSA_OID;
      } else if (signature.getAlgorithm().equals("SHA256withECDSA")) {
        return X9_SHA256_WITH_ECDSA_OID;
      } else {
        return null;
      }
    }
    
    public OutputStream getOutputStream() {
      return outputStream;
    }
    
    public byte[] getSignature() {
      try {
        signature.update(outputStream.toByteArray());
        return signature.sign();
      } catch (GeneralSecurityException gse) {
        gse.printStackTrace();
        return null;
      }
    }
  }	
}
