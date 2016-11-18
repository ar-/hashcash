/* Penny Post - A postage system for email
 * Copyright (c) 2006-2007  Gregory Rubin <grrubin@gmail.com> 
 * http://www.nettgryppa.com 
*  Copyright (C) 2007  Aliasgar Lokhandwala <d7@freepgs.com> 
 * http://pennypost.sourceforge.net/
 * 
 * CashUtils.java: Provides common helper methods
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.security.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

public final class CashUtils {
	/**
	 * Date format string
	 */
	public static final String m_sDtFormat = "yyMMdd";

	/**
	 * Gets the calendar at current time at GMT
	 * @author Ali
	 */
	public static Calendar getGMTCalendar() {
		return Calendar.getInstance(TimeZone.getTimeZone("GMT"));
	}

	/**
	 * Gets the calendar at given time at GMT
	 * @author Ali
	 */
	public static Calendar getGMTCalendarAtTime(String sTime)
			throws ParseException {
		SimpleDateFormat dtFormat = new SimpleDateFormat(m_sDtFormat);
		Calendar newDate = getGMTCalendar();
		newDate.setTime(dtFormat.parse(sTime));
		return newDate;
	}
	
	/**
	 * Converts a 8 byte array of unsigned bytes to an long
	 * 
	 * @param b
	 *            an array of 8 unsigned bytes
	 * @return a long representing the bytes
	 * 
	 * @author Gregory Rubin
	 */
	public static long makeLong(byte[] b) {
		long l = 0;
		l |= b[0] & 0xFF;
		l <<= 8;
		l |= b[1] & 0xFF;
		l <<= 8;
		l |= b[2] & 0xFF;
		l <<= 8;
		l |= b[3] & 0xFF;
		l <<= 8;
		l |= b[4] & 0xFF;
		l <<= 8;
		l |= b[5] & 0xFF;
		l <<= 8;
		l |= b[6] & 0xFF;
		l <<= 8;
		l |= b[7] & 0xFF;
		return l;
	}

	/**
	 * Converts a 4 byte array of unsigned bytes to an long
	 * 
	 * @param b
	 *            an array of 4 unsigned bytes
	 * @return a long representing the unsigned int
	 * 
	 * @author Gregory Rubin
	 */
	public static long unsignedIntToLong(byte[] b) {
		long l = 0;
		l |= b[0] & 0xFF;
		l <<= 8;
		l |= b[1] & 0xFF;
		l <<= 8;
		l |= b[2] & 0xFF;
		l <<= 8;
		l |= b[3] & 0xFF;
		return l;
	}

	/**
	 * Counts the number of leading zeros in a byte array.
	 * 
	 * @author Gregory Rubin
	 */
	public static int numberOfLeadingZeros(byte[] values) {
		int result = 0;
		int temp = 0;
		for (int i = 0; i < values.length; i++) {

			temp = numberOfLeadingZeros(values[i]);

			result += temp;
			if (temp != 8)
				break;
		}

		return result;
	}

	/**
	 * Returns the number of leading zeros in a bytes binary representation.
	 * 
	 * @author Gregory Rubin
	 */
	public static int numberOfLeadingZeros(byte value) {
		if (value < 0)
			return 0;
		if (value < 1)
			return 8;
		else if (value < 2)
			return 7;
		else if (value < 4)
			return 6;
		else if (value < 8)
			return 5;
		else if (value < 16)
			return 4;
		else if (value < 32)
			return 3;
		else if (value < 64)
			return 2;
		else if (value < 128)
			return 1;
		else
			return 0;
	}

	/**
	 * Converts a 32 bit value to an array of bytes. Reverse of
	 * unsignedIntToLong
	 * 
	 * @param val
	 *            The 32-bit value to convert
	 * @return an array containing 4 bytes extracted from the value
	 * 
	 * @author Ali
	 * @see #unsignedIntToLong(byte[])
	 */
	public static byte[] toBytes(final long val) {
		byte[] bytes = new byte[4];
		bytes[3] = (byte) (val & 0xFF);
		bytes[2] = (byte) ((val & 0xFF00) >>> 8);
		bytes[1] = (byte) ((val & 0xFF0000) >>> 16);
		bytes[0] = (byte) ((val & 0xFF000000) >>> 32);
		return bytes;
	}
}
