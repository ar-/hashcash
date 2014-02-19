/* Penny Post - A postage system for email
 * Copyright (C) 2007  Aliasgar Lokhandwala <d7@freepgs.com> 
 * http://pennypost.sourceforge.net/
 *
 * PennyPost.java: Provides implementation of the stamp program
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

package com.security.ppost;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.logging.Logger;

import com.security.cpu.hashcash.HashCash;
import com.security.mem.mbound.MBound;
import com.security.util.CashUtils;

public class PennyPost {
	public static final String m_sVersionStr = "Penny Post version 1.2";
	public static final String m_sAlgoSupportStr = "Supports HashCash v0 & v1, MBound v0";
	public static final String m_sCopyrightStr = "Copyright(c) 2007-2008 Aliasgar Lokhandwala <d7@freepgs.com>";
	private static Logger m_Logger = Logger
			.getLogger(PennyPost.class.getName());

	/**
	 * This class is simply used to hold constants that server as hashkeys for
	 * params
	 * 
	 * @author Ali
	 */
	private class HashKeys {
		public static final String OPERATION = "op";
		public static final String ALGORITHM = "algo";
		public static final String VALUE = "val";
		public static final String VERSION = "ver";
		public static final String PATHLEN = "pathlen";
		public static final String RESOURCE = "resource";
		public static final String DATE = "gendate";
		public static final String DATEDIFF = "gendatediff";
		public static final String EXTENSIONS = "extensions";
		public static final String OUTFILE = "outfile";
		public static final String TOKEN = "token";
		public static final String MINVALUE = "minval";
		public static final String MINPATH = "minpath";
		public static final String MAXPATH = "maxpath";
		public static final String TOKENONLY = "tokenonly";
	}

	/**
	 * Parses command-line params and puts parsed values in suppled Hashtable.
	 * This function will display help and quit if there is an error in parsing
	 * params. Also minor commands like help and version are processed directly
	 * by it.
	 * 
	 * @param args
	 *            the args passed to main
	 * @param params
	 *            Will contain algorithm name and params if the function returns
	 *            true.
	 * @return true if a generate or verify operation must be carried out, false
	 *         if no other action needs to be carried out.
	 * @throws ParseException
	 */
	private static boolean parseArgs(String[] args,
			Hashtable<String, Object> params) throws ParseException {

		String arg;

		// 1-mint, 2-check, 0-all other non conflicting
		// operations
		int iOperation = 0;

		int i = 0;
		while (i < args.length) {
			arg = args[i++].trim();

			if ("-o".compareToIgnoreCase(arg) == 0) {
				String sOutFile = args[i++].trim();
				m_Logger.info("Output will be saved in: " + sOutFile);
				params.put(HashKeys.OUTFILE, sOutFile);
			}

			if ("-d".compareToIgnoreCase(arg) == 0) {
				params.put(HashKeys.DATE, CashUtils
						.getGMTCalendarAtTime(args[i++]));
			}

			if ("-t".compareToIgnoreCase(arg) == 0) {
				params.put(HashKeys.TOKENONLY, true);
			}

			if ("-e".compareToIgnoreCase(arg) == 0) {
				params.put(HashKeys.EXTENSIONS, args[i++]);
			}

			if ("-x".compareToIgnoreCase(arg) == 0) {
				params.put(HashKeys.DATEDIFF, new Long(args[i++]));
			}

			if ("-m".compareToIgnoreCase(arg) == 0 && iOperation == 0) {
				try {
					// mint cash
					m_Logger.info("Reading mint cash params...");
					iOperation = 1;
					params.put(HashKeys.OPERATION, iOperation);

					String sAlgo = args[i++].trim();

					params.put(HashKeys.ALGORITHM, sAlgo);
					params.put(HashKeys.VERSION, new Integer(args[i++]));
					params.put(HashKeys.VALUE, new Integer(args[i++]));
					if ("mbound".equalsIgnoreCase(sAlgo)) {
						params.put(HashKeys.PATHLEN, new Integer(args[i++]));
					}
					params.put(HashKeys.RESOURCE, args[i++]);
				} catch (Exception e) {
					throw new IllegalArgumentException(
							"Insufficient parameters");
				}
			}

			if ("-c".compareToIgnoreCase(arg) == 0 && iOperation == 0) {
				try {
					// verify cash
					m_Logger.info("Reading verify cash params...");
					iOperation = 2;
					params.put(HashKeys.OPERATION, iOperation);

					String sAlgo = args[i++].trim();

					params.put(HashKeys.ALGORITHM, sAlgo);

					params.put(HashKeys.MINVALUE, new Integer(args[i++]));

					if ("mbound".equalsIgnoreCase(sAlgo)) {
						params.put(HashKeys.MINPATH, new Integer(args[i++]));
						params.put(HashKeys.MAXPATH, new Integer(args[i++]));
					}

					params.put(HashKeys.TOKEN, args[i++]);
				} catch (Exception ex) {
					throw new IllegalArgumentException(
							"Insufficient parameters");
				}
			}

			if ("-v".compareToIgnoreCase(arg) == 0 && iOperation == 0) {
				showVersion();
				// no other command can be carried out
				return false;
			}

			if ("-h".compareToIgnoreCase(arg) == 0 && iOperation == 0) {
				showHelp();
				// no other command can be carried out
				return false;
			}
		}

		// return true to process params further only if a valid operation needs
		// to be performed
		if (iOperation > 0)
			return true;
		else
			showHelp();

		return false;
	}

	/**
	 * Show version information
	 */
	private static void showVersion() {
		System.out.println(m_sVersionStr);
		System.out.println(m_sAlgoSupportStr);
		System.out.println(m_sCopyrightStr);

		System.out.println("");
		System.out.println("Using Java Runtime from "
				+ System.getProperty("java.vendor") + " v"
				+ System.getProperty("java.version"));
		System.out.println("");

		System.out
				.println("This program is free software; you can redistribute it and/or");
		System.out
				.println("modify it under the terms of the GNU General Public");
		System.out
				.println("License as published by the Free Software Foundation; either");
		System.out
				.println("version 3 of the License, or (at your option) any later version.");
		System.out.println("");
	}

	/**
	 * Show Help
	 */
	private static void showHelp() {
		showVersion();
		System.out
				.println("Mint Hashcash: \n\tppost -m hashcash <version> <value> <resource> [-d <date-YYMMDD>]\n\t[-e <extensions>] [-o outputfile] [-t]");
		System.out
				.println("Verify Hashcash: \n\tppost -c hashcash <min-value> <token> [-x <date-diff-days>]\n\t[-o outputfile]");
		System.out
				.println("Mint MBound: \n\tppost -m mbound <version> <value> <pathlen> <resource>\n\t[-d <date-YYMMDD>] [-e <extension>] [-o outputfile] [-t]");
		System.out
				.println("Verify MBound: \n\tppost -c mbound <min-value> <min-path> <max-path> <token>\n\t[-x <date-diff-days>] [-o outputfile]");

	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Hashtable<String, Object> params = new Hashtable<String, Object>();
		String token = "";
		String sOutFile = null;
		try {
			if (parseArgs(args, params)) {
				Integer iOperation = (Integer) params.get(HashKeys.OPERATION);
				sOutFile = (String) params.get(HashKeys.OUTFILE);

				if (params.get(HashKeys.TOKENONLY) == null) {
					token = "OK/";
				}

				switch (iOperation) {
				case 1:
					token += genCash(params);
					break;
				case 2:
					token += verCash(params);
					break;
				}

				m_Logger.info("Result: " + token);

				if (sOutFile != null) {
					writeToFile(sOutFile, token);
				} else {
					System.out.println(token);
				}
			}
			
			//all is well return 0 exit code
			System.exit(0);
		} catch (Exception e) {

			m_Logger.warning("Token not generated due to error: "
					+ e.getMessage());

			token = "ERR/" + e.getMessage();
			if (sOutFile != null) {
				try {
					writeToFile(sOutFile, token);
				} catch (IOException e1) {
					m_Logger
							.severe("Error while writing error info to output file "
									+ e1.getMessage());
				}
			} else {
				System.out.println(token);
			}
			
			//return a non zero exit code
			System.exit(1);
		}
	}

	/**
	 * Write supplied token to file.
	 * 
	 * @param outFile
	 *            The file path to write to
	 * @param token
	 *            The information to be written
	 * @throws IOException
	 */
	private static void writeToFile(String outFile, String token)
			throws IOException {
		BufferedWriter outputStream = null;
		try {
			outputStream = new BufferedWriter(new FileWriter(outFile, false));
			outputStream.write(token);
			outputStream.newLine();
			m_Logger.info("Result dumped to file");
		} finally {
			if (outputStream != null)
				outputStream.close();
		}

	}

	/**
	 * Generate cash using supplied params
	 * 
	 * @param params
	 * @return The cash token
	 * @throws NoSuchAlgorithmException
	 */
	private static String genCash(Hashtable<String, Object> params)
			throws NoSuchAlgorithmException {
		String sAlgo = (String) params.get(HashKeys.ALGORITHM);
		String token = null;

		String sRes = (String) params.get(HashKeys.RESOURCE);
		String sExt = (String) params.get(HashKeys.EXTENSIONS);
		Calendar dtGen = (Calendar) params.get(HashKeys.DATE);
		int iVal = (Integer) params.get(HashKeys.VALUE);
		int iVer = (Integer) params.get(HashKeys.VERSION);

		if ("mbound".equalsIgnoreCase(sAlgo)) {
			MBound result = null;
			int iPathlen = (Integer) params.get(HashKeys.PATHLEN);
			m_Logger.info("Minting MBound/" + iVer + "/" + iVal + "/"
					+ iPathlen + "/" + sRes + " " + dtGen + " " + sExt);
			// call the correct function based on available params
			if (sExt != null && dtGen != null) {
				result = MBound.mintCash(sRes, sExt, dtGen, iVal, iPathlen,
						iVer);
			} else if (sExt != null) {
				result = MBound.mintCash(sRes, sExt, iVal, iPathlen, iVer);
			} else if (dtGen != null) {
				result = MBound.mintCash(sRes, dtGen, iVal, iPathlen, iVer);
			} else {
				result = MBound.mintCash(sRes, iVal, iPathlen, iVer);
			}
			token = result.getToken();
		} else {
			HashCash result = null;
			m_Logger.info("Minting Hashcash/" + iVer + "/" + iVal + "/" + sRes
					+ " " + dtGen + " " + sExt);
			// call the correct function based on available params
			if (sExt != null && dtGen != null) {
				result = HashCash.mintCash(sRes, sExt, dtGen, iVal, iVer);
			} else if (sExt != null) {
				result = HashCash.mintCash(sRes, sExt, iVal, iVer);
			} else if (dtGen != null) {
				result = HashCash.mintCash(sRes, dtGen, iVal, iVer);
			} else {
				result = HashCash.mintCash(sRes, iVal, iVer);
			}
			token = result.getToken();
		}
		return token;
	}

	/**
	 * Verify supplied cash token
	 * 
	 * @param params
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static String verCash(Hashtable<String, Object> params)
			throws NoSuchAlgorithmException {
		String sAlgo = (String) params.get(HashKeys.ALGORITHM);
		String token = (String) params.get(HashKeys.TOKEN);
		int iMinVal = (Integer) params.get(HashKeys.MINVALUE);
		boolean result = false;
		if ("mbound".equalsIgnoreCase(sAlgo)) {
			int iMinPath = (Integer) params.get(HashKeys.MINPATH);
			int iMaxPath = (Integer) params.get(HashKeys.MAXPATH);
			MBound mbound = new MBound(token);
			if (params.get(HashKeys.DATEDIFF) != null) {
				long iDateDiff = (Long) params.get(HashKeys.DATEDIFF);
				result = mbound.verify(iMinPath, iMaxPath, iMinVal, iDateDiff);
			} else {
				result = mbound.verify(iMinPath, iMaxPath, iMinVal);
			}
		} else {
			HashCash hashcash = new HashCash(token);
			if (params.get(HashKeys.DATEDIFF) != null) {
				long iDateDiff = (Long) params.get(HashKeys.DATEDIFF);
				result = hashcash.verifyCash(iMinVal, iDateDiff);
			} else {
				result = hashcash.verifyCash(iMinVal);
			}
		}

		if (result)
			return "verified";

		return "invalid";
	}
}
