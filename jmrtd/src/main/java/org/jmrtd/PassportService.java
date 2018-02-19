/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id$
 */

package org.jmrtd;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.protocol.AAProtocol;
import org.jmrtd.protocol.AAResult;
import org.jmrtd.protocol.BACProtocol;
import org.jmrtd.protocol.BACResult;
import org.jmrtd.protocol.CAProtocol;
import org.jmrtd.protocol.CAResult;
import org.jmrtd.protocol.PACEProtocol;
import org.jmrtd.protocol.PACEResult;
import org.jmrtd.protocol.SecureMessagingWrapper;
import org.jmrtd.protocol.TAProtocol;
import org.jmrtd.protocol.TAResult;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * Card service for reading files (such as data groups) and using the BAC and AA
 * protocols on the passport. Defines secure messaging. Defines active
 * authentication.
 *
 * Based on Doc 9303.
 * Originally based on ICAO-TR-PKI and ICAO-TR-LDS.
 *
 * Usage:
 *
 * <pre>
 *        open() ==&gt;&lt;br /&gt;
 *        sendSelectApplet() ==&gt;&lt;br /&gt;
 *        doBAC(...) ==&gt;&lt;br /&gt;
 *        doAA() ==&gt;&lt;br /&gt;
 *        getInputStream(...)&lt;sup&gt;*&lt;/sup&gt; ==&gt;&lt;br /&gt;
 *        close()
 * </pre>
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision:352 $
 */
public class PassportService extends PassportAPDUService {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Card Access. */
  public static final short EF_CARD_ACCESS = 0x011C;

  /** Card Security. */
  public static final short EF_CARD_SECURITY = 0x011D;

  /** File identifier for data group 1. Data group 1 contains the MRZ. */
  public static final short EF_DG1 = 0x0101;

  /** File identifier for data group 2. Data group 2 contains face image data. */
  public static final short EF_DG2 = 0x0102;

  /** File identifier for data group 3. Data group 3 contains finger print data. */
  public static final short EF_DG3 = 0x0103;

  /** File identifier for data group 4. Data group 4 contains iris data. */
  public static final short EF_DG4 = 0x0104;

  /** File identifier for data group 5. Data group 5 contains displayed portrait. */
  public static final short EF_DG5 = 0x0105;

  /** File identifier for data group 6. Data group 6 is RFU. */
  public static final short EF_DG6 = 0x0106;

  /** File identifier for data group 7. Data group 7 contains displayed signature. */
  public static final short EF_DG7 = 0x0107;

  /** File identifier for data group 8. Data group 8 contains data features. */
  public static final short EF_DG8 = 0x0108;

  /** File identifier for data group 9. Data group 9 contains structure features. */
  public static final short EF_DG9 = 0x0109;

  /** File identifier for data group 10. Data group 10 contains substance features. */
  public static final short EF_DG10 = 0x010A;

  /** File identifier for data group 11. Data group 11 contains additional personal details. */
  public static final short EF_DG11 = 0x010B;

  /** File identifier for data group 12. Data group 12 contains additional document details. */
  public static final short EF_DG12 = 0x010C;

  /** File identifier for data group 13. Data group 13 contains optional details. */
  public static final short EF_DG13 = 0x010D;

  /** File identifier for data group 14. Data group 14 contains security infos. */
  public static final short EF_DG14 = 0x010E;

  /** File identifier for data group 15. Data group 15 contains the public key used for Active Authentication. */
  public static final short EF_DG15 = 0x010F;

  /** File identifier for data group 16. Data group 16 contains person(s) to notify. */
  public static final short EF_DG16 = 0x0110;

  /** The security document. */
  public static final short EF_SOD = 0x011D;

  /** The data group presence list. */
  public static final short EF_COM = 0x011E;

  /**
   * Contains EAC CVA references. Note: this can be overridden by a file
   * identifier in the DG14 file (in a TerminalAuthenticationInfo). Check DG14
   * first. Also, this file does not have a header tag, like the others.
   */
  public static final short EF_CVCA = 0x011C;

  /** Short file identifier for card access file. */
  public static final byte SFI_CARD_ACCESS = 0x1C;

  /** Short file identifier for card security file. */
  public static final byte SFI_CARD_SECURITY = 0x1D;

  /** Short file identifier for file. */
  public static final byte SFI_DG1 = 0x01;

  /** Short file identifier for file. */
  public static final byte SFI_DG2 = 0x02;

  /** Short file identifier for file. */
  public static final byte SFI_DG3 = 0x03;

  /** Short file identifier for file. */
  public static final byte SFI_DG4 = 0x04;

  /** Short file identifier for file. */
  public static final byte SFI_DG5 = 0x05;

  /** Short file identifier for file. */
  public static final byte SFI_DG6 = 0x06;

  /** Short file identifier for file. */
  public static final byte SFI_DG7 = 0x07;

  /** Short file identifier for file. */
  public static final byte SFI_DG8 = 0x08;

  /** Short file identifier for file. */
  public static final byte SFI_DG9 = 0x09;

  /** Short file identifier for file. */
  public static final byte SFI_DG10 = 0x0A;

  /** Short file identifier for file. */
  public static final byte SFI_DG11 = 0x0B;

  /** Short file identifier for file. */
  public static final byte SFI_DG12 = 0x0C;

  /** Short file identifier for file. */
  public static final byte SFI_DG13 = 0x0D;

  /** Short file identifier for file. */
  public static final byte SFI_DG14 = 0x0E;

  /** Short file identifier for file. */
  public static final byte SFI_DG15 = 0x0F;

  /** Short file identifier for file. */
  public static final byte SFI_DG16 = 0x10;

  /** Short file identifier for file. */
  public static final byte SFI_COM = 0x1E;

  /** Short file identifier for file. */
  public static final byte SFI_SOD = 0x1D;

  /** Short file identifier for file. */
  public static final byte SFI_CVCA = 0x1C;

  /** The default maximal blocksize used for unencrypted APDUs. */
  public static final int DEFAULT_MAX_BLOCKSIZE = 224;

  /** The normal maximal tranceive length of APDUs. */
  public static final int NORMAL_MAX_TRANCEIVE_LENGTH = 256;

  /** The extended maximal tranceive length of APDUs. */
  public static final int EXTENDED_MAX_TRANCEIVE_LENGTH = 65536;

  /**
   * The file read block size, some passports cannot handle large values.
   */
  private int maxBlockSize;

  private boolean isOpen;

  private SecureMessagingWrapper wrapper;

  private int maxTranceiveLength;

  private boolean isICAOAppletSelected;

  private MRTDFileSystem rootFileSystem;

  private MRTDFileSystem icaoFileSystem;

  /**
   * Creates a new passport service for accessing the passport.
   *
   * @param service another service which will deal with sending the APDUs to the card
   * @param maxTranceiveLength maximum length for APDUs
   * @param maxBlockSize maximum buffer size for plain text APDUs
   * @param isSFIEnabled whether short file identifiers should be used for read binaries when possible
   *
   * @throws CardServiceException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives:
   *             <ul>
   *                 <li>Cipher: "DESede/CBC/Nopadding"</li>
   *                 <li>Mac: "ISO9797Alg3Mac"</li>
   *             </ul>
   */
  public PassportService(CardService service, int maxTranceiveLength, int maxBlockSize, boolean isSFIEnabled) throws CardServiceException {
    super(service);
    this.maxTranceiveLength = maxTranceiveLength;
    this.maxBlockSize = maxBlockSize;
    this.rootFileSystem = new MRTDFileSystem(this, isSFIEnabled);
    this.icaoFileSystem = new MRTDFileSystem(this, isSFIEnabled);
    this.isICAOAppletSelected = false;
    this.isOpen = false;
  }

  /**
   * Opens a session to the card. As of 0.4.10 this no longer auto selects the passport application,
   * caller is responsible to call #sendSelectApplet(boolean) now.
   *
   * @throws CardServiceException on error
   */
  @Override
  public void open() throws CardServiceException {
    if (isOpen()) {
      return;
    }
    synchronized(this) {
      super.open();
      isOpen = true;
    }
  }

  /**
   * Selects the MRTD card side applet. If PACE has been executed successfully previously, then the card has authenticated
   * us and a secure messaging channel has already been established. If not, then the caller should request BAC execution as a next
   * step.
   *
   * @param hasPACESucceeded indicates whether PACE has been executed successfully (in which case a secure messaging channel has been established)
   *
   * @throws CardServiceException on error
   */
  public void sendSelectApplet(boolean hasPACESucceeded) throws CardServiceException {
    if (isICAOAppletSelected) {
      LOGGER.info("Re-selecting ICAO applet");
    }

    if (hasPACESucceeded) {
      /* Use SM as set up by doPACE() */
      sendSelectApplet(wrapper, APPLET_AID);
    } else {
      /* Use plain messaging to select the applet, caller will have to do doBAC. */
      sendSelectApplet(null, APPLET_AID);
    }

    isICAOAppletSelected = true;
  }

  /**
   * Gets whether this service is open.
   *
   * @return a boolean that indicates whether this service is open
   */
  @Override
  public boolean isOpen() {
    return isOpen;
  }

  /**
   * Selects a file within the MRTD application.
   *
   * @param fid a file identifier
   */
  @Override
  public synchronized void sendSelectFile(short fid) throws CardServiceException {
    sendSelectFile(wrapper, fid);
  }

  /**
   * Sends a {@code READ BINARY} command using a short file identifier to the passport,
   * using the wrapper when a secure channel has been set up.
   *
   * @param offset offset into the file
   * @param le the expected length of the file to read
   * @param isTLVEncodedOffsetNeeded whether to encode the offset in a TLV object (typically for offset larger than 32767)
   *
   * @return a byte array of length {@code le} with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendReadBinary(int offset, int le, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
    return sendReadBinary(wrapper, NO_SFI, offset, le, false, isTLVEncodedOffsetNeeded);
  }

  /**
   * Sends a {@code READ BINARY} command using a short file identifier to the passport,
   * using the wrapper when a secure channel has been set up.
   *
   * @param sfi the short file identifier byte as int value (between 0 and 255)
   * @param offset offset into the file
   * @param le the expected length of the file to read
   * @param isTLVEncodedOffsetNeeded whether to encode the offset in a TLV object (typically for offset larger than 32767)
   *
   * @return a byte array of length {@code le} with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendReadBinary(int sfi, int offset, int le, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
    return sendReadBinary(wrapper, sfi, offset, le, true, isTLVEncodedOffsetNeeded);
  }

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   *
   * @param bacKey the key based on the document number,
   *               the card holder's birth date,
   *               and the document's expiration date
   *
   * @return the BAC result
   *
   * @throws CardServiceException if authentication failed
   */
  public synchronized BACResult doBAC(BACKeySpec bacKey) throws CardServiceException {
    BACResult bacResult = (new BACProtocol(this)).doBAC(bacKey);
    wrapper = bacResult.getWrapper();
    return bacResult;
  }

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   * It does BAC using kEnc and kMac keys, usually calculated
   * from the document number, the card holder's date of birth,
   * and the card's date of expiry.
   *
   * A secure messaging channel is set up as a result.
   *
   * @param kEnc static 3DES key required for BAC
   * @param kMac static 3DES key required for BAC
   *
   * @return the result
   *
   * @throws CardServiceException if authentication failed
   * @throws GeneralSecurityException on security primitives related problems
   */
  public synchronized BACResult doBAC(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException {
    BACResult bacResult = (new BACProtocol(this)).doBAC(kEnc, kMac);
    wrapper = bacResult.getWrapper();
    return bacResult;
  }

  /**
   * Performs the PACE 2.0 / SAC protocol.
   * A secure messaging channel is set up as a result.
   *
   * @param keySpec the MRZ
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   *
   * @return the result
   *
   * @throws PACEException on error
   */
  public synchronized PACEResult doPACE(AccessKeySpec keySpec, String oid, AlgorithmParameterSpec params) throws PACEException {
    PACEResult paceResult = (new PACEProtocol(this, wrapper)).doPACE(keySpec, oid, params);
    wrapper = paceResult.getWrapper();
    return paceResult;
  }

  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   * A new secure messaging channel is set up as a result.
   *
   * @param keyId passport's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the object identifier indicating the public key algorithm used
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the Chip Authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  public synchronized CAResult doCA(BigInteger keyId, String oid, String publicKeyOID, PublicKey publicKey) throws CardServiceException {
    CAResult caResult = (new CAProtocol(this, wrapper)).doCA(keyId, oid, publicKeyOID, publicKey);
    wrapper = caResult.getWrapper();
    return caResult;
  }

  /* From BSI-03110 v1.1, B.2:
   *
   * <pre>
   * The following sequence of commands SHALL be used to implement Terminal Authentication:
   *   1. MSE:Set DST
   *   2. PSO:Verify Certificate
   *   3. MSE:Set AT
   *   4. Get Challenge
   *   5. External Authenticate
   * Steps 1 and 2 are repeated for every CV certificate to be verified
   * (CVCA Link Certificates, DV Certificate, IS Certificate).
   * </pre>
   */
  /**
   * Performs <i>Terminal Authentication</i> (TA) part of EAC (version 1). For details see
   * TR-03110 ver. 1.11.
   *
   * In short, we feed the sequence of terminal certificates to the card for verification,
   * get a challenge from the card, sign it with the terminal private key, and send the result
   * back to the card for verification.
   *
   * @param caReference reference issuer
   * @param terminalCertificates terminal certificate chain
   * @param terminalKey terminal private key
   * @param taAlg algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param documentNumber the document number
   *
   * @return the Terminal Authentication result
   *
   * @throws CardServiceException on error
   */
  public synchronized TAResult doTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, CAResult chipAuthenticationResult, String documentNumber) throws CardServiceException {
    TAResult taResult = (new TAProtocol(this, wrapper)).doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, documentNumber);
    return taResult;
  }

  /**
   * Performs <i>Terminal Authentication</i> (TA) part of EAC (version 1). For details see
   * TR-03110 ver. 1.11.
   *
   * In short, we feed the sequence of terminal certificates to the card for verification,
   * get a challenge from the card, sign it with the terminal private key, and send the result
   * back to the card for verification.
   *
   * @param caReference reference issuer
   * @param terminalCertificates terminal certificate chain
   * @param terminalKey terminal private key
   * @param taAlg algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param paceResult the PACE result
   *
   * @return the Terminal Authentication result
   *
   * @throws CardServiceException on error
   */
  public synchronized TAResult doTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, CAResult chipAuthenticationResult, PACEResult paceResult) throws CardServiceException {
    TAResult taResult = (new TAProtocol(this, wrapper)).doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, paceResult);
    return taResult;
  }

  /**
   * Performs the <i>Active Authentication</i> protocol.
   *
   * @param publicKey the public key to use (usually read from the card)
   * @param digestAlgorithm the digest algorithm to use, or null
   * @param signatureAlgorithm signature algorithm
   * @param challenge challenge
   *
   * @return a boolean indicating whether the card was authenticated
   *
   * @throws CardServiceException on error
   */
  public AAResult doAA(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge) throws CardServiceException {
    AAResult aaResult = (new AAProtocol(this, wrapper)).doAA(publicKey, digestAlgorithm, signatureAlgorithm, challenge);
    return aaResult;
  }

  /**
   * Closes this service.
   */
  @Override
  public void close() {
    try {
      wrapper = null;
      super.close();
    } finally {
      isOpen = false;
    }
  }

  /**
   * Returns the maximum tranceive length of (protected) APDUs.
   *
   * @return the maximum APDU tranceive length
   */
  public int getMaxTranceiveLength() {
    return maxTranceiveLength;
  }

  /**
   * Gets the wrapper. Returns {@code null} until access control has been performed.
   *
   * @return the wrapper
   */
  public APDUWrapper getWrapper() {
    return wrapper;
  }

  /**
   * Gets the file as an input stream indicated by a file identifier.
   * The resulting input stream will send APDUs to the card.
   *
   * @param fid ICAO file identifier
   *
   * @return the file as an input stream
   *
   * @throws CardServiceException if the file cannot be read
   */
  public synchronized CardFileInputStream getInputStream(short fid) throws CardServiceException {
    if (!isICAOAppletSelected) {
      synchronized(rootFileSystem) {
        rootFileSystem.selectFile(fid);
        return new CardFileInputStream(maxBlockSize, rootFileSystem);
      }
    } else {
      synchronized(icaoFileSystem) {
        icaoFileSystem.selectFile(fid);
        return new CardFileInputStream(maxBlockSize, icaoFileSystem);
      }
    }
  }
}
