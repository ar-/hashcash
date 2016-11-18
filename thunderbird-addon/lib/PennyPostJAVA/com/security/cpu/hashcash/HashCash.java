/* HashCash - A CPU intensive cash algorithm implementation
 * Copyright (c) 2006  Gregory Rubin <grrubin@gmail.com> 
 * http://www.nettgryppa.com
 *
 * HashCash.java: Provides implementation for Hashcash
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 3 of the 
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.security.cpu.hashcash;

import java.util.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.security.NoSuchAlgorithmException;

import com.security.util.CashUtils;

public final class HashCash implements Comparable<HashCash> {
	public static final int DefaultVersion = 1;
	private static final int hashLength = 160;
	private static long milliFor16 = -1;

	private String myToken;
	private int myValue;
	private Calendar myDate;
	private String myExtensions;
	private int myVersion;
	private String myResource;

	// Constructors

	/**
	 * Parses and validates a HashCash.
	 * 
	 * Token format:<br>
	 * Ver1- ver:date:resource:rand:counter<br>
	 * Ver2- ver:bits:date:resource:ext:rand:counter
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public HashCash(String cash) throws NoSuchAlgorithmException {
		myToken = cash;
		String[] parts = cash.split(":");
		myVersion = Integer.parseInt(parts[0]);
		if (myVersion < 0 || myVersion > 1)
			throw new IllegalArgumentException(
					"Only supported versions are 0 and 1");

		if ((myVersion == 0 && parts.length != 6)
				|| (myVersion == 1 && parts.length != 7))
			throw new IllegalArgumentException("Improperly formed HashCash");

		try {
			int index = 1;
			if (myVersion == 1)
				myValue = Integer.parseInt(parts[index++]);
			else
				myValue = 0;

			myDate = CashUtils.getGMTCalendarAtTime(parts[index++]);
			myResource = parts[index++];

			if (myVersion == 1)
				myExtensions = parts[index++];
			else
				myExtensions = "";

			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(cash.getBytes());
			byte[] tempBytes = md.digest();
			int measuredValue = CashUtils.numberOfLeadingZeros(tempBytes);

			if (myVersion == 0)
				myValue = measuredValue;

		} catch (java.text.ParseException ex) {
			throw new IllegalArgumentException("Improperly formed HashCash", ex);
		}
	}

	public boolean verifyCash(int iMinZeros) throws NoSuchAlgorithmException {
		return verifyCash(iMinZeros, 0, false);
	}

	public boolean verifyCash(int iMinZeros, long dateDiff)
			throws NoSuchAlgorithmException {
		return verifyCash(iMinZeros, dateDiff, true);
	}

	private boolean verifyCash(int iMinZeros, long dateDiff, boolean bDate)
			throws NoSuchAlgorithmException {
		if (myValue < iMinZeros)
			return false;

		if (bDate) {
			if (((CashUtils.getGMTCalendar().getTimeInMillis() - myDate
					.getTimeInMillis()) / (1000 * 60 * 60 * 24)) > dateDiff) {
				return false;
			}
		}

		if (myVersion != 0) {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(myToken.getBytes());
			byte[] tempBytes = md.digest();
			int measuredValue = CashUtils.numberOfLeadingZeros(tempBytes);
			if (measuredValue < myValue)
				return false;
		}

		return true;
	}

	private HashCash() throws NoSuchAlgorithmException {
	}

	/**
	 * Mints a version 1 HashCash using now as the date
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, int value)
			throws NoSuchAlgorithmException {
		Calendar now = CashUtils.getGMTCalendar();
		return mintCash(resource, "", now, value, DefaultVersion);
	}

	/**
	 * Mints a HashCash using now as the date
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @param version
	 *            Which version to mint. Only valid values are 0 and 1
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, int value, int version)
			throws NoSuchAlgorithmException {
		Calendar now = CashUtils.getGMTCalendar();
		return mintCash(resource, "", now, value, version);
	}

	/**
	 * Mints a version 1 HashCash
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, Calendar date, int value)
			throws NoSuchAlgorithmException {
		return mintCash(resource, "", date, value, DefaultVersion);
	}

	/**
	 * Mints a HashCash
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @param version
	 *            Which version to mint. Only valid values are 0 and 1
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, Calendar date, int value,
			int version) throws NoSuchAlgorithmException {
		return mintCash(resource, "", date, value, version);
	}

	/**
	 * Mints a version 1 HashCash using now as the date
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @param extensions
	 *            Extra data to be encoded in the HashCash
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, String extensions,
			int value) throws NoSuchAlgorithmException {
		Calendar now = CashUtils.getGMTCalendar();
		return mintCash(resource, extensions, now, value, DefaultVersion);
	}

	/**
	 * Mints a HashCash using now as the date
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @param extensions
	 *            Extra data to be encoded in the HashCash
	 * @param version
	 *            Which version to mint. Only valid values are 0 and 1
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, String extensions,
			int value, int version) throws NoSuchAlgorithmException {
		Calendar now = CashUtils.getGMTCalendar();
		return mintCash(resource, extensions, now, value, version);
	}

	/**
	 * Mints a version 1 HashCash
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @param extensions
	 *            Extra data to be encoded in the HashCash
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, String extensions,
			Calendar date, int value) throws NoSuchAlgorithmException {
		return mintCash(resource, extensions, date, value, DefaultVersion);
	}

	/**
	 * Mints a HashCash
	 * 
	 * @param resource
	 *            the string to be encoded in the HashCash
	 * @param extensions
	 *            Extra data to be encoded in the HashCash
	 * @param version
	 *            Which version to mint. Only valid values are 0 and 1
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static HashCash mintCash(String resource, String extensions,
			Calendar date, int value, int version)
			throws NoSuchAlgorithmException {
		if (version < 0 || version > 1)
			throw new IllegalArgumentException(
					"Only supported versions are 0 and 1");

		if (value < 0 || value > hashLength)
			throw new IllegalArgumentException("Value must be between 0 and "
					+ hashLength);

		if (resource.contains(":"))
			throw new IllegalArgumentException(
					"Resource may not contain a colon.");

		HashCash result = new HashCash();

		MessageDigest md = MessageDigest.getInstance("SHA1");

		result.myResource = resource;
		result.myExtensions = extensions;
		result.myDate = date;
		result.myVersion = version;

		String prefix;

		SimpleDateFormat dateFormat = new SimpleDateFormat(
				CashUtils.m_sDtFormat);
		switch (version) {
		case 0:
			prefix = version + ":" + dateFormat.format(date.getTime()) + ":"
					+ resource + ":";
			result.myToken = generateCash(prefix, value, md);
			md.reset();
			md.update(result.myToken.getBytes());
			result.myValue = CashUtils.numberOfLeadingZeros(md.digest());
			break;

		case 1:
			result.myValue = value;
			prefix = version + ":" + value + ":"
					+ dateFormat.format(date.getTime()) + ":" + resource + ":"
					+ extensions + ":";
			result.myToken = generateCash(prefix, value, md);
			break;

		default:
			throw new IllegalArgumentException(
					"Only supported versions are 0 and 1");
		}

		return result;
	}

	// Accessors
	/**
	 * Two objects are considered equal if they are both of type HashCash and
	 * have an identical string representation
	 */
	public boolean equals(Object obj) {
		if (obj instanceof HashCash)
			return toString().equals(obj.toString());
		else
			return super.equals(obj);
	}

	/**
	 * Returns the canonical string representation of the HashCash
	 */
	public String toString() {
		return myToken;
	}

	/**
	 * Extra data encoded in the HashCash
	 */
	public String getExtensions() {
		return myExtensions;
	}

	/**
	 * The primary resource being protected
	 */
	public String getResource() {
		return myResource;
	}

	/**
	 * The minting date
	 */
	public Calendar getDate() {
		return myDate;
	}

	/**
	 * The value of the HashCash (e.g. how many leading zero bits it has)
	 */
	public int getValue() {
		return myValue;
	}

	/**
	 * Which version of HashCash is used here
	 */
	public int getVersion() {
		return myVersion;
	}

	/**
	 * The generated/stored token
	 * 
	 * @return
	 */
	public String getToken() {
		return myToken;
	}

	// Private utility functions
	/**
	 * Actually tries various combinations to find a valid hash. Form is of
	 * prefix + random_hex + ":" + random_hex
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	private static String generateCash(String prefix, int value,
			MessageDigest md) throws NoSuchAlgorithmException {
		SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
		byte[] tmpBytes = new byte[8];
		rnd.nextBytes(tmpBytes);
		long random1 = CashUtils.makeLong(tmpBytes);
		rnd.nextBytes(tmpBytes);
		long random2 = CashUtils.makeLong(tmpBytes);
		rnd.nextBytes(tmpBytes);
		long counter = CashUtils.makeLong(tmpBytes);

		prefix = prefix + Long.toHexString(random1) + Long.toHexString(random2)
				+ ":";

		String temp;
		int tempValue;
		byte[] bArray;
		do {
			counter++;
			temp = prefix + Long.toHexString(counter);
			md.reset();
			md.update(temp.getBytes());
			bArray = md.digest();
			tempValue = CashUtils.numberOfLeadingZeros(bArray);
		} while (tempValue < value);

		return temp;
	}

	/**
	 * Estimates how many milliseconds it would take to mint a cash of the
	 * specified value.
	 * <ul>
	 * <li>NOTE1: Minting time can vary greatly in fact, half of the time it
	 * will take half as long)
	 * <li>NOTE2: The first time that an estimation function is called it is
	 * expensive (on the order of seconds). After that, it is very quick.
	 * </ul>
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static long estimateTime(int value) throws NoSuchAlgorithmException {
		initEstimates();
		return (long) (milliFor16 * Math.pow(2, value - 16));
	}

	/**
	 * Estimates what value (e.g. how many bits of collision) are required for
	 * the specified length of time.
	 * <ul>
	 * <li>NOTE1: Minting time can vary greatly in fact, half of the time it
	 * will take half as long)
	 * <li>NOTE2: The first time that an estimation function is called it is
	 * expensive (on the order of seconds). After that, it is very quick.
	 * </ul>
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	public static int estimateValue(int secs) throws NoSuchAlgorithmException {
		initEstimates();
		int result = 0;
		long millis = secs * 1000 * 65536;
		millis /= milliFor16;

		while (millis > 1) {
			result++;
			millis /= 2;
		}

		return result;
	}

	/**
	 * Seeds the estimates by determining how long it takes to calculate a 16bit
	 * collision on average.
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If SHA1 is not a supported Message Digest
	 * @author Gregory Rubin
	 */
	private static void initEstimates() throws NoSuchAlgorithmException {
		if (milliFor16 == -1) {
			long duration;
			duration = Calendar.getInstance().getTimeInMillis();
			for (int i = 0; i < 11; i++) {
				mintCash("estimation", 16);
			}
			duration = Calendar.getInstance().getTimeInMillis() - duration;
			milliFor16 = (duration / 10);
		}
	}

	/**
	 * Compares the value of two HashCashes
	 * 
	 * @param other
	 * @see java.lang.Comparable#compareTo(Object)
	 */
	public int compareTo(HashCash other) {
		if (null == other)
			throw new NullPointerException();

		return Integer.valueOf(getValue()).compareTo(
				Integer.valueOf(other.getValue()));
	}

	/*
	 * @param args @throws NoSuchAlgorithmException
	 */
	/*
	 * public static void main(String[] args) throws NoSuchAlgorithmException { //
	 * TODO Auto-generated method stub HashCash hc = new HashCash(
	 * "1:5:070706:axl687@bham.ac.uk::1dc5c82b:74d3520b");
	 * System.out.println(hc.verifyCash(5)); }
	 */

}
