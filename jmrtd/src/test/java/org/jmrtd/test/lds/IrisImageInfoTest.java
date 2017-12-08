package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.iso19794.IrisImageInfo;
import org.jmrtd.lds.iso19794.IrisInfo;

import junit.framework.TestCase;

public class IrisImageInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
  
  public void testToString() {
    try {
      IrisImageInfo info = createTestObject();
      assertNotNull(info);
      String asString = info.toString();
      assertNotNull(asString);
      assertTrue(asString.startsWith("IrisImageInfo"));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testLength() {
    IrisImageInfo irisImageInfo = createTestObject();
    int imageLength = irisImageInfo.getImageLength();
    int recordLength = (int)irisImageInfo.getRecordLength();
    assertTrue(imageLength < recordLength);
  }

  public static IrisImageInfo createTestObject() {
    try {
      BufferedImage image = new BufferedImage(300, 200, BufferedImage.TYPE_BYTE_GRAY);
      ByteArrayOutputStream encodedImageOut = new ByteArrayOutputStream();
      ImageIO.write(image, "jpg", encodedImageOut);
      encodedImageOut.flush();
      byte[] imageBytes = encodedImageOut.toByteArray();
      IrisImageInfo irisImageInfo = new IrisImageInfo(1, image.getWidth(), image.getHeight(), new ByteArrayInputStream(imageBytes), imageBytes.length, IrisInfo.IMAGEFORMAT_MONO_JPEG);
      return irisImageInfo;
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
