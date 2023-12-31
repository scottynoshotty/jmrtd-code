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

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.icao.DG11File;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class DG11FileTest extends TestCase {

  private Logger LOGGER = Logger.getLogger("org.jmrtd");

  public DG11FileTest(String name) {
    super(name);
  }

  public void testToString() {
    DG11File dg11File = createTestObject();
    String expectedResult = "DG11File [, [], , 19711019, [], [], , , , , , [], ]";
    assertEquals(dg11File.toString(), expectedResult);
  }

  public void testDecodeEncode() {
    byte[] simpleDG11 = new byte[] {
        0x6B, 0x34, 0x5C, 0x10, 0x5F, 0x0E, 0x5F, 0x10,
        0x5F, 0x2B, 0x5F, 0x12, 0x5F, 0x13, 0x5F, 0x14,
        0x5F, 0x15, 0x5F, 0x18, 0x5F, 0x0E, 0x02, 0x3C,
        0x3C, 0x5F, 0x10, 0x00, 0x5F, 0x2B, 0x08, 0x31,
        0x39, 0x37, 0x31, 0x31, 0x30, 0x31, 0x39, 0x5F,
        0x12, 0x00, 0x5F, 0x13, 0x00, 0x5F, 0x14, 0x00,
        0x5F, 0x15, 0x00, 0x5F, 0x18, 0x00
    };

    try {
      DG11File dg11File = new DG11File(new ByteArrayInputStream(simpleDG11));
      byte[] encoded = dg11File.getEncoded();

      assertEquals(Hex.bytesToHexString(simpleDG11), Hex.bytesToHexString(encoded));
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testReflexive() {
    testReflexive(createTestObject());
    testReflexive(createComplexTestObject());
  }

  public void testReflexive(DG11File dg11File) {
    try {
      if (dg11File == null) {
        fail("Input file is null");
      }

      byte[] encoded = dg11File.getEncoded();
      assertNotNull(encoded);
      //			LOGGER.info("DEBUG: encoded =\n" + Hex.bytesToPrettyString(encoded));

      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      DG11File copy = new DG11File(in);

      assertNotNull(copy);
      assertEquals(dg11File, copy);

      byte[] encodedCopy = copy.getEncoded();
      assertNotNull(encodedCopy);
      //			LOGGER.info("DEBUG: encoded =\n" + Hex.bytesToPrettyString(encodedCopy));

      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(copy.getEncoded()));

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  /**
   * Ronny is a fictional character.
   * Any resemblance to living persons is pure coincidence.
   */
  public void testRonny() {
    byte[] bytes = {
        0x6B, 0x2F, 0x5C, 0x02, 0x5F, 0x0E, 0x5F, 0x0E,
        0x28, 0x57, 0x49, 0x43, 0x48, 0x45, 0x52, 0x53,
        0x3C, 0x53, 0x43, 0x48, 0x52, 0x45, 0x55, 0x52,
        0x3C, 0x3C, 0x52, 0x4F, 0x4E, 0x41, 0x4C, 0x44,
        0x55, 0x53, 0x3C, 0x4A, 0x4F, 0x48, 0x41, 0x4E,
        0x4E, 0x45, 0x53, 0x3C, 0x4D, 0x41, 0x52, 0x49,
        0x41
    };

    ByteArrayInputStream in = new ByteArrayInputStream(bytes);
    try {
      DG11File file = new DG11File(in);
      String primary = "WICHERS" + "<" + "SCHREUR";
      String secondary = "RONALDUS" + "<" + "JOHANNES" + "<" + "MARIA";
      assertEquals(file.getNameOfHolder(), primary + "<<" + secondary);
      //				assertEquals(file.getFullNamePrimaryIdentifier(), "WICHERS<SCHREUR");
      //				assertEquals(file.getFullNameSecondaryIdentifiers().size(), 3);
      //				assertEquals(file.getFullNameSecondaryIdentifiers().get(0), "RONALDUS");
      //				assertEquals(file.getFullNameSecondaryIdentifiers().get(1), "JOHANNES");
      //				assertEquals(file.getFullNameSecondaryIdentifiers().get(2), "MARIA");
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testSpecSample() {
    byte[] bytes = {
        0x6B, /* L */ 0x63,
        0x5C, /* L = 10, i.e. 5 tags */ 0x0A,
        0x5F, 0x0E,
        0x5F, 0x11,
        0x5F, 0x42,
        0x5F, 0x12,
        0x5F, 0x13,
        0x5F, 0x0E, /* L */ 0x0D,
        'S', 'M', 'I', 'T', 'H', '<', '<', 'J', 'O', 'H', 'N', '<', 'J',
        0x5F, 0x11, /* L */ 0x0A,
        'A', 'N', 'Y', 'T', 'O', 'W', 'N', '<', 'M', 'N',
        0x5F, 0x42, /* L */ 0x17,
        '1', '2', '3', ' ', 'M', 'A', 'P', 'L', 'E', ' ', 'R', 'D', '<', 'A', 'N', 'Y', 'T', 'O', 'W', 'N', '<', 'M', 'N',
        0x5F, 0x12, /* L */ 0x0E,
        '1', '-', '6', '1', '2', '-', '5', '5', '5', '-', '1', '2', '1', '2',
        0x5F, 0x13, /* L */ 0x0C,
        'T', 'R', 'A', 'V', 'E', 'L', '<', 'A', 'G', 'E', 'N', 'T'
    };

    ByteArrayInputStream in = new ByteArrayInputStream(bytes);
    try {
      DG11File file = new DG11File(in);
      String primary = "SMITH";
      String secondary = "JOHN" + "<" + "J";
      assertEquals(file.getNameOfHolder(), primary + "<<" + secondary);
      //				assertEquals(file.getFullNamePrimaryIdentifier(), "SMITH");
      //				assertEquals(file.getFullNameSecondaryIdentifiers().size(), 2);
      //				assertEquals(file.getFullNameSecondaryIdentifiers().get(0), "JOHN");
      //				assertEquals(file.getFullNameSecondaryIdentifiers().get(1), "J");
      assertEquals(file.getPlaceOfBirth().size(), 2);
      assertEquals(file.getPlaceOfBirth().get(0), "ANYTOWN");
      assertEquals(file.getPlaceOfBirth().get(1), "MN");
      assertEquals(file.getPermanentAddress().size(), 3);
      assertEquals(file.getPermanentAddress().get(0), "123 MAPLE RD");
      assertEquals(file.getPermanentAddress().get(1), "ANYTOWN");
      assertEquals(file.getPermanentAddress().get(2), "MN");
      assertEquals(file.getTelephone(), "1-612-555-1212");
      assertEquals(file.getProfession(), "TRAVEL<AGENT");
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testComplex() {
    try {
      DG11File dg11 = createComplexTestObject();
      byte[] encoded = dg11.getEncoded();
      //			LOGGER.info("DEBUG: encoded = \n" + Hex.bytesToPrettyString(encoded));
      DG11File copy = new DG11File(new ByteArrayInputStream(encoded));
      byte[] copyEncoded = copy.getEncoded();
      //			LOGGER.info("DEBUG: copy encoded = \n" + Hex.bytesToPrettyString(copy.getEncoded()));
      assert(Arrays.equals(encoded, copyEncoded));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  /**
   * https://sourceforge.net/p/jmrtd/bugs/65/
   */
  public void testNullDate() {
    String nameOfHolder = "SOME<MRZ_FORMATTED<NAME";
    DG11File dg11 = new DG11File(nameOfHolder, null, null, (Date)null, null, null, null, null, null, null, null, null, null);
    assertEquals(nameOfHolder, dg11.getNameOfHolder());
    assertNull(dg11.getFullDateOfBirth());
  }

  public static DG11File createComplexTestObject() {
    String fullNamePrimaryIdentifier = "TEST";
    String fullNameSecondaryIdentifiers = "FIRST" + "<" + "SECOND";
    List<String> otherNames = Arrays.asList(new String[] { "FIRST OTHER", "SECOND OTHER", "THIRD OTHER" });
    String nameOfHolder = fullNamePrimaryIdentifier + "<<" + fullNameSecondaryIdentifiers;
    String personalNumber = "123456789";
    Calendar cal = Calendar.getInstance();
    cal.set(1971, 10 - 1, 19);
    Date fullDateOfBirth = cal.getTime();
    List<String> placeOfBirth = new ArrayList<String>();
    List<String> permanentAddress = new ArrayList<String>();
    String telephone = "";
    String profession = "";
    String title = "";
    String personalSummary = "";
    byte[] proofOfCitizenship = null;
    List<String> otherValidTDNumbers = new ArrayList<String>();
    String custodyInformation = "";
    return new DG11File(nameOfHolder, otherNames, personalNumber,
        fullDateOfBirth, placeOfBirth, permanentAddress,
        telephone, profession, title,
        personalSummary, proofOfCitizenship,
        otherValidTDNumbers, custodyInformation);
  }

  public static DG11File createTestObject() {
    String nameOfHolder = "";
    List<String> otherNames = new ArrayList<String>();
    String personalNumber = "";
    Calendar cal = Calendar.getInstance();
    cal.set(1971, 10 - 1, 19);
    Date fullDateOfBirth = cal.getTime();
    List<String> placeOfBirth = new ArrayList<String>();
    List<String> permanentAddress = new ArrayList<String>();
    String telephone = "";
    String profession = "";
    String title = "";
    String personalSummary = "";
    byte[] proofOfCitizenship = null;
    List<String> otherValidTDNumbers = new ArrayList<String>();
    String custodyInformation = "";
    return new DG11File(nameOfHolder, otherNames, personalNumber,
        fullDateOfBirth, placeOfBirth, permanentAddress,
        telephone, profession, title,
        personalSummary, proofOfCitizenship,
        otherValidTDNumbers, custodyInformation);
  }

  public void testFile(InputStream in) {
    try {
      testReflexive(new DG11File(in));
    } catch (IOException ioe) {
      fail(ioe.toString());
    }
  }
}
