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
 * $Id: $
 */

package org.jmrtd;

import javax.crypto.spec.SecretKeySpec;

/**
 * A key for PACE.
 *
 * @author The JMRTD Team (info@jmrtd.org)
 *
 * @version $Revision: $
 *
 * (Contributions by g.giorkhelidze.)
 */
public class PACESecretKeySpec extends SecretKeySpec {
  
  private static final long serialVersionUID = 1L;

  private byte keyReference;

  public PACESecretKeySpec(byte[] key, int offset, int len, String algorithm, byte paceKeyReference) {
    super(key, offset, len, algorithm);
    this.keyReference = paceKeyReference;
  }

  public PACESecretKeySpec(byte[] key, String algorithm, byte paceKeyReference) {
    super(key, algorithm);
    this.keyReference = paceKeyReference;
  }

  public byte getKeyReference() {
    return keyReference;
  }
}
