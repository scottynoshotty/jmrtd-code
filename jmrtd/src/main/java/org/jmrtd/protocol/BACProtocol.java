/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2017  The JMRTD team
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

package org.jmrtd.protocol;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.jmrtd.BACKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.Util;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * The Basic Access Control protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision$
 *
 * @since 0.5.6
 */
public class BACProtocol {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private PassportService service;
  private Random random;

  /**
   * Constructs a BAC protocol instance.
   *
   * @param service the service to send APDUs
   */
  public BACProtocol(PassportService service) {
    this.service = service;
    this.random = new SecureRandom();
  }

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   *
   * @param bacKey the key based on the document number,
   *               the card holder's birth date,
   *               and the document's expiry date
   *
   * @return the BAC result
   *
   * @throws CardServiceException if authentication failed
   */
  public BACResult doBAC(BACKeySpec bacKey) throws CardServiceException {
    try {
      byte[] keySeed = computeKeySeedForBAC(bacKey);
      SecretKey kEnc = Util.deriveKey(keySeed, Util.ENC_MODE);
      SecretKey kMac = Util.deriveKey(keySeed, Util.MAC_MODE);

      SecureMessagingWrapper wrapper = doBACStep(kEnc, kMac);
      return new BACResult(bacKey, wrapper);
    } catch (CardServiceException cse) {
      LOGGER.log(Level.WARNING, "BAC failed", cse);
      throw cse;
    } catch (GeneralSecurityException gse) {
      throw new CardServiceException("Error during BAC", gse);
    }
  }

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   * It does BAC using kEnc and kMac keys, usually calculated
   * from the document number, the card holder's date of birth,
   * and the card's date of expiry.
   *
   * @param kEnc static 3DES key required for BAC
   * @param kMac static 3DES key required for BAC
   *
   * @return the new secure messaging wrapper
   *
   * @throws CardServiceException if authentication failed
   * @throws GeneralSecurityException on security primitives related problems
   */
  public BACResult doBAC(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException {
    return new BACResult(doBACStep(kEnc, kMac));
  }

  private SecureMessagingWrapper doBACStep(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException {
    byte[] rndICC = service.sendGetChallenge();
    byte[] rndIFD = new byte[8];
    random.nextBytes(rndIFD);
    byte[] kIFD = new byte[16];
    random.nextBytes(kIFD);
    byte[] response = service.sendMutualAuth(rndIFD, rndICC, kIFD, kEnc, kMac);
    byte[] kICC = new byte[16];
    System.arraycopy(response, 16, kICC, 0, 16);
    /* FIXME: We're not checking the other 16 bytes?!? -- MO */

    byte[] keySeed = new byte[16];
    for (int i = 0; i < 16; i++) {
      keySeed[i] = (byte) ((kIFD[i] & 0xFF) ^ (kICC[i] & 0xFF));
    }
    SecretKey ksEnc = Util.deriveKey(keySeed, Util.ENC_MODE);
    SecretKey ksMac = Util.deriveKey(keySeed, Util.MAC_MODE);
    long ssc = computeSendSequenceCounter(rndICC, rndIFD);

    return new DESedeSecureMessagingWrapper(ksEnc, ksMac, ssc);
  }

  public static byte[] computeKeySeedForBAC(BACKeySpec bacKey) throws GeneralSecurityException {
    String documentNumber = bacKey.getDocumentNumber();
    String dateOfBirth = bacKey.getDateOfBirth();
    String dateOfExpiry = bacKey.getDateOfExpiry();

    if (dateOfBirth == null || dateOfBirth.length() != 6) {
      throw new IllegalArgumentException("Wrong date format used for date of birth. Expected yyMMdd, found " + dateOfBirth);
    }
    if (dateOfExpiry == null || dateOfExpiry.length() != 6) {
      throw new IllegalArgumentException("Wrong date format used for date of expiry. Expected yyMMdd, found " + dateOfExpiry);
    }
    if (documentNumber == null) {
      throw new IllegalArgumentException("Wrong document number. Found " + documentNumber);
    }

    documentNumber = fixDocumentNumber(documentNumber);

    return computeKeySeedForBAC(documentNumber, dateOfBirth, dateOfExpiry);
  }

  public static long computeSendSequenceCounter(byte[] rndICC, byte[] rndIFD) {
    if (rndICC == null || rndICC.length != 8
        || rndIFD == null || rndIFD.length != 8) {
      throw new IllegalStateException("Wrong length input");
    }
    long ssc = 0;
    for (int i = 4; i < 8; i++) {
      ssc <<= 8;
      ssc += rndICC[i] & 0x000000FF;
    }
    for (int i = 4; i < 8; i++) {
      ssc <<= 8;
      ssc += rndIFD[i] & 0x000000FF;
    }
    return ssc;
  }

  /**
   * Computes the static key seed to be used in BAC KDF, based on information from the MRZ.
   *
   * @param documentNumber a string containing the document number
   * @param dateOfBirth a string containing the date of birth (YYMMDD)
   * @param dateOfExpiry a string containing the date of expiry (YYMMDD)
   *
   * @return a byte array of length 16 containing the key seed
   *
   * @throws GeneralSecurityException on security error
   */
  private static byte[] computeKeySeedForBAC(String documentNumber, String dateOfBirth, String dateOfExpiry) throws GeneralSecurityException {
    return Util.computeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", true);
  }

  /**
   * Returns the document number, including trailing '<' until length 9.
   * 
   * @param documentNumber the original document number
   * 
   * @return the documentNumber with at least length 9
   */
  private static String fixDocumentNumber(String documentNumber) {
    StringBuilder maxDocumentNumber = new StringBuilder(documentNumber == null ? "" : documentNumber.replace('<', ' ').trim().replace(' ', '<'));
    while (maxDocumentNumber.length() < 9) {
      maxDocumentNumber.append('<');
    }
    return maxDocumentNumber.toString();
  }
}
