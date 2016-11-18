/* MBound - A memory intensive cash algorithm implementation
 * Copyright (C) 2007  Aliasgar Lokhandwala <d7@freepgs.com> 
 * http://pennypost.sourceforge.net/
 *
 * MBound.java: Provides implementation of MBound
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
package com.security.mem.mbound;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import com.security.util.CashUtils;

/**
 * This algorithm involves a large fixed forever array T, now of 2^22 truly
 * random 32-bit integers.We have |T| = 2^22 and w = 32.
 * 
 * This class uses longs (64 bits) instead of integers (32-bits) because JAVA
 * does not support unsigned integers, so the only way to store a 32 bit
 * unsigned number is inside a long. NOTE: All calculations are done assuming
 * only 32 bits in the long value
 * 
 * @author Ali
 */
public final class MBound {
	public static final int DefaultVersion = 0;
	/**
	 * Used while generating cash using mintCashNow() to append a dummy date
	 * value
	 * 
	 * @see #mintCashNow()
	 */
	public static final String m_sDummyDate = "820101";

	/**
	 * Hash length in bits. SHA-1 has a length of 160 bits.
	 */
	private static final int m_iHashLen = 160;

	/**
	 * Size of T is 2^22 i.e. 16 MB
	 */
	private static final int m_iSizeOfArrayT = 0x400000;

	/**
	 * Size of A is 256
	 */
	private static final int m_iSizeOfArrayA = 256;

	/**
	 * Ensures that the fixed arrays are populated only once
	 */
	private static boolean m_bFixedArraysPopulated = false;

	/**
	 * The fixed-forever array - will be populated by populateFixedArrays() This
	 * array requires 16 MB and dominates the space needs of our memory-bound
	 * function.
	 * 
	 * Keeping them static means there will be only one for all objects this is
	 * OK as once populated these are only to be read from and never written
	 * into.
	 */
	private static long[] m_fixedArrayT = new long[m_iSizeOfArrayT];
	private static long[] m_fixedArrayA0 = new long[m_iSizeOfArrayA];

	/**
	 * A string of the format ver:zbits:pathlen:date:resource:ext:rand:counter
	 */
	private String m_sToken = "";

	/**
	 * The number of zero bits in the result
	 */
	private int m_iClaimedZeros;

	/**
	 * The length of the path
	 */
	private int m_iPathLen;

	/**
	 * Date of generation of token, defaults to now
	 */
	private Calendar m_clDate = CashUtils.getGMTCalendar();

	/**
	 * Any extra name=value pairs
	 */
	private String m_sExtensions = "";

	/**
	 * The version number of the token format, currently 0
	 */
	private int m_iVersion = 0;

	/**
	 * String identifying for who the token is to be generated. Mostly
	 * recipients email address
	 */
	private String m_sResource;

	private MBound() throws IllegalArgumentException {
		if (!m_bFixedArraysPopulated) {
			populateFixedArrays();
		}
	}

	/**
	 * Creates a new MBound parsing the input token
	 * 
	 * @param sToken
	 *            a string of the format
	 *            ver:zbits:pathlen:date:resource:ext:rand:counter. Must not be
	 *            NULL.
	 * @throws FileNotFoundException
	 */
	public MBound(String sToken) throws IllegalArgumentException {
		assert sToken != null;

		parse(sToken);
		if (!m_bFixedArraysPopulated) {
			populateFixedArrays();
		}
	}

	/**
	 * Populates this object using supplied token. The token is not
	 * cryptographically verified. Call verify() to verify the token
	 * cryptographically.
	 * 
	 * @see #verify(int, int, int, long)
	 * 
	 * @param sToken
	 *            a string of the format
	 *            ver:zbits:pathlen:date:resource:ext:rand:counter. Must not be
	 *            NULL
	 */
	public void parse(String sToken) {
		assert sToken != null;

		// save the token
		m_sToken = sToken;

		// parse the token
		String[] parts = m_sToken.split(":");

		// version - for now is fixed to 0
		m_iVersion = Integer.parseInt(parts[0]);
		if (m_iVersion != 0)
			throw new IllegalArgumentException("Only supported version is 0");

		if (parts.length != 8)
			throw new IllegalArgumentException("Improperly formed Token");

		try {
			int i = 1;
			m_iClaimedZeros = Integer.parseInt(parts[i++]);
			m_iPathLen = Integer.parseInt(parts[i++]);

			m_clDate = CashUtils.getGMTCalendarAtTime(parts[i++]);

			// resource a.k.a the recipient email address
			m_sResource = parts[i++];
			m_sExtensions = parts[i++];
		} catch (java.text.ParseException ex) {
			throw new IllegalArgumentException("Improperly formed Token", ex);
		}
	}

	/**
	 * Populates T(m_fixedArrayT) and A0(m_fixedArrayA0) from files
	 */
	private synchronized void populateFixedArrays() {
		if (m_bFixedArraysPopulated)
			return;

		// both these are loaded from the jar
		final String fileNameT = "fndef/functionT.dat";
		final String fileNameA = "fndef/functionA.dat";

		DataInputStream in;
		in = new DataInputStream(new BufferedInputStream(getClass()
				.getClassLoader().getResourceAsStream(fileNameT)));

		try {
			for (int i = 0; i < m_iSizeOfArrayT; i++) {
				m_fixedArrayT[i] = in.readInt() & 0xFFFFFFFFL;
				assert m_fixedArrayT[i] >= 0;
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			try {
				in.close();
			} catch (IOException e) {
			}
		}

		in = new DataInputStream(new BufferedInputStream(getClass()
				.getClassLoader().getResourceAsStream(fileNameA)));

		try {
			for (int i = 0; i < m_iSizeOfArrayA; i++) {
				m_fixedArrayA0[i] = in.readInt() & 0xFFFFFFFFL;
				assert m_fixedArrayA0[i] >= 0;
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			try {
				in.close();
			} catch (IOException e) {
			}
		}

		m_bFixedArraysPopulated = true;
	}

	/**
	 * Aka H0: initializes the array A This method is written separately as
	 * initialization of A can be done in many ways.
	 * 
	 * @param prefix
	 *            a string used as the base for the computation usually of the
	 *            format ver:zbits:pathlen:date:resource:ext:rand:counter
	 * @return the initialized array A of 256 32-bit values
	 * @throws NoSuchAlgorithmException
	 */
	private static long[] initialize(String prefix)
			throws NoSuchAlgorithmException {
		long[] arrayA = m_fixedArrayA0.clone();
		MessageDigest md = MessageDigest.getInstance("SHA1");

		md.update(prefix.getBytes());
		byte[] dig = md.digest();
		int siz = dig.length;
		byte[] byte4 = new byte[4];
		for (int i = 0, j = 0; i < m_iSizeOfArrayA; i++, j += 4) {
			byte4[0] = dig[j % siz];
			byte4[1] = dig[(j + 1) % siz];
			byte4[2] = dig[(j + 2) % siz];
			byte4[3] = dig[(j + 3) % siz];
			arrayA[i] = arrayA[i] ^ CashUtils.unsignedIntToLong(byte4);
		}
		return arrayA;
	}

	/**
	 * Calculates and returns result after iPathLength iterations. This function
	 * can be used both to verify and to compute a path.
	 * 
	 * @param iPathLen
	 *            the number of iterations
	 * @param md
	 *            the MessageDigest (algorithm) to use (will be reset)
	 * 
	 * @param sPrefix
	 *            a string used as the base for the computation usually of the
	 *            ver:zbits:pathlen:date:resource:ext:rand:counter
	 * @return
	 * @throws NoSuchAlgorithmException
	 */

	private static byte[] calcPath(String sPrefix, final int iPathLen,
			MessageDigest md) throws NoSuchAlgorithmException {
		assert m_bFixedArraysPopulated;
		assert iPathLen > 1;

		long[] arrayA = initialize(sPrefix);

		int c = 0;
		int i = 0, j = 0;
		long tmp, q = 0;
		// extract the last 22 bits of A as c
		// 0x3FFFFF = 0011 1111 1111 1111 1111 1111
		c = (int) ((arrayA[255] & 0x3FFFFFL) % m_iSizeOfArrayT);
		assert c >= 0;
		for (i = 0; i < iPathLen; i++) {
			assert (i % m_iSizeOfArrayA) >= 0;
			j = (int) ((j + (arrayA[(i % m_iSizeOfArrayA)]) % m_iSizeOfArrayA) % m_iSizeOfArrayA);
			assert j >= 0;
			arrayA[(i % m_iSizeOfArrayA)] = (arrayA[(i % m_iSizeOfArrayA)] + m_fixedArrayT[c]) % 0xFFFFFFFFL;
			arrayA[i % m_iSizeOfArrayA] = rightCyclicShift11(arrayA[i
					% m_iSizeOfArrayA]);

			// swap A[i], A[j]
			tmp = arrayA[i % m_iSizeOfArrayA] & 0xFFFFFFFFL;
			arrayA[i % m_iSizeOfArrayA] = arrayA[j];
			arrayA[j] = tmp;
			q = ((arrayA[i % m_iSizeOfArrayA] % m_iSizeOfArrayA) + (arrayA[j] % m_iSizeOfArrayA))
					% m_iSizeOfArrayA;
			assert q >= 0;
			c = (int) ((m_fixedArrayT[c] ^ arrayA[(int) q]) % m_iSizeOfArrayT);
			assert c >= 0;
		}

		md.reset();
		for (i = 0; i < m_iSizeOfArrayA; i++) {
			md.update(CashUtils.toBytes(arrayA[i]));
		}
		byte[] dig = md.digest();
		return dig;
	}

	private static long rightCyclicShift11(long l) {
		return (Integer.rotateRight((int) l, 11)) & 0xFFFFFFFFL;
	}

	/**
	 * Verifies the token held in this object
	 * 
	 * @param iMinPathLen
	 *            the minimum path length acceptable
	 * @param iMaxPathLen
	 *            the maximum path length acceptable, a high value here can
	 *            allow a DoS against the verifier.
	 * @param iMinZeros
	 *            the minimum hardness for the problem
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verify(int iMinPathLen, int iMaxPathLen, int iMinZeros)
			throws NoSuchAlgorithmException {
		return verifyCash(iMinPathLen, iMaxPathLen, iMinZeros, 0, false);
	}

	/**
	 * Verifies the token held in this object considering the time at which the
	 * token was generated and the current time.
	 * 
	 * All time comparisons are done using current GMT
	 * 
	 * @param iMinPathLen
	 *            the minimum path length acceptable
	 * @param iMaxPathLen
	 *            the maximum path length acceptable, a high value here can
	 *            allow a DoS against the verifier.
	 * @param iMinZeros
	 *            the minimum hardness for the problem
	 * @param dateDiff
	 *            acceptable staleness of the message in #no of days
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verify(int iMinPathLen, int iMaxPathLen, int iMinZeros,
			long dateDiff) throws NoSuchAlgorithmException {
		return verifyCash(iMinPathLen, iMaxPathLen, iMinZeros, dateDiff, true);
	}

	/**
	 * Verifies if the current token is valid
	 * 
	 * @param iMinPathLen
	 *            the minimum path length acceptable
	 * @param iMaxPathLen
	 *            the maximum path length acceptable, a high value here can
	 *            allow a DoS against the verifier.
	 * @param iMinZeros
	 *            the minimum hardness for the problem
	 * @param dateDiff
	 *            acceptable staleness of the message in #no of days
	 * @param vDate
	 *            set true if the dateDiff parameter is valid
	 * 
	 * @return true if the token is verified, false otherwise
	 * @throws NoSuchAlgorithmException
	 */
	private boolean verifyCash(int iMinPathLen, int iMaxPathLen, int iMinZeros,
			long dateDiff, boolean vDate) throws NoSuchAlgorithmException {
		if (m_iPathLen < iMinPathLen || m_iPathLen > iMaxPathLen)
			return false;

		if (m_iClaimedZeros < iMinZeros)
			return false;

		if (vDate) {
			if (((CashUtils.getGMTCalendar().getTimeInMillis() - m_clDate
					.getTimeInMillis()) / (1000 * 60 * 60 * 24)) > dateDiff) {
				return false;
			}
		}

		MessageDigest md = MessageDigest.getInstance("SHA1");

		byte[] bArray = calcPath(m_sToken, m_iPathLen, md);
		int iRealZeros = CashUtils.numberOfLeadingZeros(bArray);

		if (m_iClaimedZeros > iRealZeros)
			return false;

		return true;

	}

	public static MBound mintCash(String sResource, int iZeros, int iPathLen)
			throws NoSuchAlgorithmException {
		return mintCash(sResource, "", CashUtils.getGMTCalendar(), iZeros,
				iPathLen, DefaultVersion);
	}

	public static MBound mintCash(String sResource, int iZeros, int iPathLen,
			int iVersion) throws NoSuchAlgorithmException {
		return mintCash(sResource, "", CashUtils.getGMTCalendar(), iZeros,
				iPathLen, iVersion);
	}

	public static MBound mintCash(String sResource, String sExtensions,
			int iZeros, int iPathLen, int iVersion)
			throws NoSuchAlgorithmException {
		return mintCash(sResource, sExtensions, CashUtils.getGMTCalendar(),
				iZeros, iPathLen, iVersion);
	}

	public static MBound mintCash(String sResource, Calendar clDate,
			int iZeros, int iPathLen, int iVersion)
			throws NoSuchAlgorithmException {
		return mintCash(sResource, "", clDate, iZeros, iPathLen, iVersion);
	}

	public static MBound mintCash(String sResource, String sExtensions,
			Calendar clDate, int iZeros, int iPathLen)
			throws NoSuchAlgorithmException {
		return mintCash(sResource, sExtensions, clDate, iZeros, iPathLen,
				DefaultVersion);

	}

	/**
	 * Actually generates the cash token. Parameters should not be null.
	 * 
	 * @param sResource
	 * @param sExtensions
	 * @param clDate
	 * @param iZeros
	 * @param iPathLen
	 * @param iVersion
	 * @return The MBound object with the correctly computed token. Verify
	 *         should never fail on this returned object.
	 * @throws NoSuchAlgorithmException
	 */
	public static MBound mintCash(String sResource, String sExtensions,
			Calendar clDate, int iZeros, int iPathLen, int iVersion)
			throws NoSuchAlgorithmException {
		if (iVersion != 0)
			throw new IllegalArgumentException("Only supported version is 0");

		if (iZeros < 0 || iZeros > m_iHashLen)
			throw new IllegalArgumentException("iZeros must be between 0 and "
					+ m_iHashLen);

		if (iPathLen <= 1)
			throw new IllegalArgumentException(
					"iPathLen must be greater than 1");

		if (sResource.contains(":"))
			throw new IllegalArgumentException(
					"sResource may not contain a colon.");

		MBound result = new MBound();

		result.m_sResource = sResource;
		result.m_sExtensions = sExtensions;
		result.m_clDate = clDate;
		result.m_iVersion = iVersion;
		result.m_iClaimedZeros = iZeros;
		result.m_iPathLen = iPathLen;

		String sPrefix;
		SimpleDateFormat dtFormat = new SimpleDateFormat(CashUtils.m_sDtFormat);

		// ver:zbits:pathlen:date:resource:ext:
		sPrefix = iVersion + ":" + iZeros + ":" + iPathLen + ":"
				+ dtFormat.format(clDate.getTime()) + ":" + sResource + ":"
				+ sExtensions + ":";

		MessageDigest md = MessageDigest.getInstance("SHA1");
		SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");

		// attach a random string to the prefix
		byte[] tmpBytes = new byte[8];
		srand.nextBytes(tmpBytes);
		long random1 = CashUtils.makeLong(tmpBytes);
		srand.nextBytes(tmpBytes);
		long random2 = CashUtils.makeLong(tmpBytes);
		srand.nextBytes(tmpBytes);
		// the counter
		long k = CashUtils.makeLong(tmpBytes);

		// ver:zbits:pathlen:date:resource:ext:rand:
		sPrefix += Long.toHexString(random1) + Long.toHexString(random2) + ":";

		// Now we attach different counts and keep trying to get the right
		// number of zeros
		int tempValue;
		byte[] bArray;
		String temp;
		do {
			k++;
			temp = sPrefix + Long.toHexString(k);
			bArray = calcPath(temp, iPathLen, md);
			tempValue = CashUtils.numberOfLeadingZeros(bArray);
		} while (tempValue < iZeros);

		// save the final token
		result.m_sToken = temp;

		return result;
	}

	/**
	 * Used to generate T
	 * 
	 * @param fileName
	 *            File used to store the table data
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @see #generateAT()
	 */
	private static void generateT(final String fileName)
			throws NoSuchAlgorithmException, IOException {
		assert fileName != null;

		SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(
				new FileOutputStream(fileName)));

		System.out.println("Writing table T to: " + fileName);
		byte[] tmpBytes = new byte[4];

		try {
			// write out T
			for (int i = 0; i < m_iSizeOfArrayT; i++) {
				srand.nextBytes(tmpBytes);
				long random = CashUtils.unsignedIntToLong(tmpBytes);
				out.writeInt((int) random);
			}
		} finally {
			// close file
			out.close();
		}
		System.out.println("Done...");
	}

	/**
	 * Used to generate A
	 * 
	 * @param fileName
	 *            File used to store the table data
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @see #generateAT()
	 */
	private static void generateA(final String fileName)
			throws NoSuchAlgorithmException, IOException {
		assert fileName != null;

		SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(
				new FileOutputStream(fileName)));

		System.out.println("Writing table A to: " + fileName);
		byte[] tmpBytes = new byte[4];
		try {
			// write out A
			for (int i = 0; i < m_iSizeOfArrayA; i++) {
				srand.nextBytes(tmpBytes);
				long random = CashUtils.unsignedIntToLong(tmpBytes);
				out.writeInt((int) random);
			}
		} finally {
			// close file
			out.close();
		}
		System.out.println("Done...");
	}

	/**
	 * Use this function to generate a new A and T table set files
	 */
	@SuppressWarnings("unused")
	private static void generateAT() {
		final String fileNameT = "C:\\functionT.dat";
		final String fileNameA = "C:\\functionA.dat";

		try {
			generateT(fileNameT);
			generateA(fileNameA);
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public String getToken() {
		return m_sToken;
	}

	public String getResource() {
		return m_sResource;
	}

	public String getExtensions() {
		return m_sExtensions;
	}

	public Calendar getDate() {
		return m_clDate;
	}

	public String getDateStr() {
		SimpleDateFormat dtFormat = new SimpleDateFormat(CashUtils.m_sDtFormat);
		return dtFormat.format(m_clDate.getTime());
	}

	/**
	 * Used to test the generation algorithm
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	@SuppressWarnings("unused")
	public static void testGenCash() throws NoSuchAlgorithmException {
		// request a token with 20 zeros and path depth 5
		MBound mb = MBound.mintCash("ali.l@tcs.com", 20, 5);
		System.out.println(mb.getToken());
	}

	/**
	 * Used to test the verification algorithm
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	@SuppressWarnings("unused")
	public static void testVerifyCash() throws NoSuchAlgorithmException {
		String token = "0:20:5:070706:ali.l@tcs.com::e085a4a0:c501f0c8";
		MBound mb = new MBound(token);
		System.out.print("Verification Result: ");
		System.out.println(mb.verify(2, 10, 20));
	}

	/*
	 * Main - used solely for testing
	 * 
	 * @param args @throws NoSuchAlgorithmException
	 */
	/*
	 * public static void main(String[] args) throws NoSuchAlgorithmException {
	 * testGenCash(); testVerifyCash(); }
	 */
}
