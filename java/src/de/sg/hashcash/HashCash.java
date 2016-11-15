package de.sg.hashcash;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Random;
import java.util.TimeZone;

/*
 * Created on 05.12.2003
 */

/**
 * @author Sebastian Gesemann (sgeseman \at upb \dot de)
 */
public class HashCash
{
	/**
	 * @return one random character out of 62 ('A'..'Z','a'..'z','0'..'9')
	 */
	private static final byte getRandomChar(Random rnd) {
		int x = rnd.nextInt(62);
		if (x<10) return (byte)(48+x); // ASCII code for '0'..'9'
		x-=10;
		if (x<26) return (byte)(65+x); // ASCII code for 'A'..'Z'
		x-=26;
		return (byte)(97+x); // ASCII code for 'a'..'z'
	}

	/**
	 * @param c
	 * @return c+1 (within '0'..'9','A'..'Z','a'..'z')
	 */
	private static final byte incChar(byte c) {
		c++;
		if (c==48+10) return (byte)65;
		if (c==65+26) return (byte)97;
		if (c==97+26) return (byte)48;
		return c;
	}

	private static final void incCharArray(byte[] arr, int ofs, int len) {
		int o = ofs+len;
		for (;;) {
			o--;
			if (o<ofs) break;
			if ((arr[o] = incChar(arr[o])) != 48) break;
		}
	}

	/**
	 * @param ba
	 * @param minimum
	 * @return checks whether a bitstring (MSB first) starts at least with [minimum] zeros
	 */
	private static final boolean zeroBits(byte[] ba, int minimum) {
		int o=0;
		while (minimum>=8) {
			if (ba[o++]!=(byte)0) return false;
			minimum-=8;
		}
		if (minimum>0) {
			int m = (0xFF << (8-minimum)) & 0xFF;
			if ((ba[o] & m) != 0) return false;
		}
		return true;
	}

	private static final int countZeroBits(byte[] ba, int l) {
		int t,r = 0;
		for (int o=0; o<l;) {
			t = (ba[o++] & 0xFF) << 8;
			t |= (o<l) ? (ba[o++] & 0xFF) : 0xFF;
			if ((t & 0xFFFF) == 0) {
				r += 16;
			} else {
				if ((t & 0xFF00) == 0) { r += 8; t <<= 8; }
				if ((t & 0xF000) == 0) { r += 4; t <<= 4; }
				if ((t & 0xC000) == 0) { r += 2; t <<= 2; }
				if ((t & 0x8000) == 0) { r += 1; }
				break;
			}
		}
		return r;
	}

	/**
	 * @param prefix
	 * @param bits
	 * @return a string s with s=prefix|suffix where SHA1(s) starts with [bits] zeros
	 * @throws NoSuchAlgorithmException
	 * @throws InterruptedException
	 */
	public static final String genRawToken(String prefix, int bits, Random rnd) throws InterruptedException {
		if (bits<0 || bits>160) throw new IllegalArgumentException("'bits' parameter out of range");
		SHA1 sha1 = new SHA1();
		try {
			int pof = prefix.length();
			int pad = Math.max(11,6+bits*100/595); // compute the length of the suffix
			int lll = pof+pad;
			byte[] asBytes = new byte[lll];
			{
				byte[] temp = (prefix).getBytes("US-ASCII");
				System.arraycopy(temp,0,asBytes,0,temp.length);
			}
			for (int i=pof; i<asBytes.length; i++) {
				asBytes[i] = getRandomChar(rnd);
			}
			byte[] hash = new byte[20];
			int o;
			for (int ct=0;;) {
				sha1.reset();
				sha1.update(asBytes);
				sha1.digest(hash,0);
				if (zeroBits(hash,bits)) return new String(asBytes,"US-ASCII");
				incCharArray(asBytes,pof,pad);
				if (++ct==200) { // check every 200 SHA1 checksum calculations if we should interrupt
					ct=0;
					if (Thread.interrupted()) throw new InterruptedException();
				}
			}
		} catch (UnsupportedEncodingException e) {
			throw new InternalError("unexpected charset exception occured");
		}
	}

	/**
	 * Class for the multi-threaded mode storing the first found token
	 * @author Sebastian Gesemann
	 */
	private static final class TokenResult {
		private boolean valid = false;
		private String result = null;
		public synchronized void foundToken(String t) {
			result = t;
			valid = true;
			this.notifyAll();
		}
		public synchronized String waitForResult() throws InterruptedException {
			while (!valid) {
				this.wait();
			}
			return this.result;
		}
	}

	/**
	 * Thread-Class for calculatung a token and notifying a TokenResult object
	 * @author Sebastian Gesemann
	 */
	private static final class TokenGenThread extends Thread {
		private final TokenResult tr;
		private final String prefix;
		private final int bits;
		private final Random rnd;
		private TokenGenThread(String prefix, int bits, TokenResult tr, Random rnd) {
			this.prefix = prefix;
			this.bits = bits;
			this.tr = tr;
			this.rnd = rnd;
		}
		public void run() {
			try {
				tr.foundToken(genRawToken(prefix,bits,rnd));
			} catch (InterruptedException e) {}
		}
	}

	/**
	 * @param prefix
	 * @param bits
	 * @param threads (amount of threads trying to find a token)
	 * @return returns a string s=prefix|suffix with SHA1(s) beginning with [bits] zeros
	 * @throws NoSuchAlgorithmException
	 * @throws InterruptedException
	 */
	public static final String genRawToken(String prefix, int bits, int threads) throws InterruptedException {
		Random rnd = new Random();
		if (threads<=1) return genRawToken(prefix,bits,rnd);
		TokenResult tr = new TokenResult();
		TokenGenThread[] tgt = new TokenGenThread[threads];
		for (int i=0; i<threads; i++) { // starting all threads ...
			(tgt[i] = new TokenGenThread(prefix,bits,tr,new Random(rnd.nextLong()))).start();
		}
		try {
			String result = tr.waitForResult();
			if (result==null) throw new InternalError("unexpected exception");
			return result;
		} finally { // notify all threads to stop
			for (int i=0; i<threads; i++) {
				Thread t = tgt[i];
				if (t!=null && t.isAlive()) t.interrupt();
			}
		}
	}

	/**
	 * @param i
	 * @return returns a two-digit string (leading zero for i<10)
	 */
	public static final String twoDigits(int i) {
		return i<10 ? "0"+i : Integer.toString(i);
	}

	/**
	 * @param c
	 * @return returns a 6 character string (YYMMDD) for a given Calendar
	 */
	public static final String timeToYYMMDD(Calendar c) {
		return twoDigits(c.get(Calendar.YEAR) % 100)
		+twoDigits((c.get(Calendar.MONTH)+1) % 100)
		+twoDigits(c.get(Calendar.DAY_OF_MONTH) % 100);
	}

	/**
	 * @param chall
	 * @return returns a HashCash prefix of the form "0:YYMMDD:challange:"
	 */
	public static final String prefixForChallange(String chall) {
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		return "0:"+timeToYYMMDD(c)+":"+chall+":";
	}

	/**
	 * @param token
	 * @return returns the value of the token (ie the amount of leading zeros of its SHA1-hash)
	 * @throws NoSuchAlgorithmException
	 */
	public static final int getTokenValue(String token) {
		MessageDigest sha1 = new SHA1();
		byte[] tmp;
		try {
			byte[] hash = sha1.digest(tmp=token.getBytes("US-ASCII"),0,tmp.length);
			return countZeroBits(hash,hash.length);
		} catch (UnsupportedEncodingException e) {
			throw new InternalError("unexpected charset exception");
		}
	}

	/**
	 * @param hcToken
	 * @param partIndex 0..4
	 * @return the string part of the token
	 */
	public static final String getHCTokenPart(String hcToken, int partIndex) {
		int idx1 = 0;
		int idx2 = -1;
		while (partIndex-->=0) {
			idx1 = idx2+1;
			idx2 = hcToken.indexOf(':',idx1+1);
			if (idx2==-1) idx2=hcToken.length();
		}
		if (idx1>idx2 || idx1>=hcToken.length()) return "";
		return hcToken.substring(idx1,idx2);
	}

	/**
	 * checks whether the token is valid. a token is valid if <br>
	 * - the token is of format 0
	 * - the challange string of the token matches the given challange string
	 * - the time stamp of the token is within time1 and time2
	 * - the SHA1 hash of the token starts with at least [minbits] zero bits
	 * 
	 * @param challange
	 * @param caseSensitive
	 * @param time1  format YYMMDD
	 * @param time2  format YYMMDD
	 * @param minBits
	 * @param token
	 * @return true if the token is valid
	 * @throws NoSuchAlgorithmException
	 */
	public static final boolean isTokenOK(String challange, boolean caseSensitive, String time1, String time2, int minBits, String token) {
		for (int i=0,o1,o2=-1; i<3; i++) {
			o1 = o2+1;
			o2 = token.indexOf(':',o1+1);
			if (o2<=o1) return false;
			String part = token.substring(o1,o2);
			if ((i==0) && (!part.equals("0"))) return false;
			if (i==1) {
				for (int k=0; i<part.length(); i++) {
					char c = part.charAt(k);
					if (c<'0' || '9'<c) return false;
				}
				if ((time1.compareTo(part)>0) || (part.compareTo(time2)>0)) return false;
			}
			if (i==2) {
				if (caseSensitive) {
					if (!challange.equals(part)) return false;
				} else {
					if (!challange.equalsIgnoreCase(part)) return false;
				}
			}
		}
		return (getTokenValue(token)>=minBits);
	}

	/**
	 * Synchronized counter for the speed benchmark
	 * @author Sebastian Gesemann
	 */
	private static final class Counter {
		private int ct = 0;
		synchronized void increment(int amount) {
			ct += amount;
		}
		synchronized int get() {
			return ct;
		}
	}

	/**
	 * Thread-Class for performing SHA1 computations and incrementing a synchronized counter
	 * @author Sebastian Gesemann
	 */
	private static final class PerformanceTestThread extends Thread {
		private final Counter cc;
		PerformanceTestThread(Counter c) {
			this.cc = c;
		}
		public void run() {
			SHA1 h = new SHA1();
			int dl = h.getDigestSize();
			byte[] buff = new byte[dl];
			Counter c = this.cc;
			for (;;) {
				for (int i=0; i<0x200; i++) {
					h.reset();
					h.update(buff);
					h.digest(buff,0);
				}
				c.increment(2);
				if (this.isInterrupted()) break;
			}
		}
	}

	/**
	 * @param threads
	 * @return the cost factor
	 * @throws NoSuchAlgorithmException
	 * @throws InterruptedException
	 */
	public static final float estimateCostFactor(int threads) throws InterruptedException {
		Counter c = new Counter();
		PerformanceTestThread[] thread = new PerformanceTestThread[threads];
		for (int i=0; i<threads; i++) thread[i]=new PerformanceTestThread(c);
		long timeStart = System.currentTimeMillis();
		for (int i=0; i<threads; i++) thread[i].start();
		Thread.sleep(990);
		long timeDuration = System.currentTimeMillis() - timeStart;
		int ccc = c.get()+threads;
		for (int i=0; i<threads; i++) thread[i].interrupt();
		return timeDuration/256.f/ccc;
	}

	/**
	 * @param costFactor
	 * @param bits
	 * @return the estimated amount of time in seconds for a [bits]-bit-HC-token
	 */
	public static final float estimateCost(float costFactor, int bits) {
		return (float)(costFactor * Math.pow(2,bits) / 1000);
	}

	/**
	 * @param seconds
	 * @return a string representing the amount of time to wait in a human readable format
	 */
	public static final String humanReadableTime(float seconds) {
		if (seconds<10) {
			int asInt = Math.round(seconds*10);
			return (asInt/10)+"."+(asInt % 10)+" seconds";
		}
		if (seconds<300) {
			return Math.round(seconds)+" seconds";
		}
		if (seconds<18000) {
			return Math.round(seconds/60)+" minutes";
		}
		if (seconds<180000) {
			return Math.round(seconds/3600)+" hours";
		}
		float days = seconds/86400;
		if (days<100) {
			return Math.round(days)+" days";
		}
		if (days<1800) {
			return Math.round(days/30.4375f)+" months";
		}
		return Math.round(days/365.25d)+" years";
	}

	public final static void main(String[] args) throws InterruptedException {
		try {
			System.out.println("\nYAHCT - yet another HashCash tool - 1.0 - contact <sgeseman \\at upb \\dot de>");
			if (args==null || args.length<2) {
				System.out.println("\nSyntax:");
				System.out.println("\tyahct [options] [<challange> <bits>|<token> check]");
				System.out.println("oprions are");
				System.out.println("\t-r       challange is used as raw prefix");
				System.out.println("\t-e       enables cost estimation (default for bits>=24)");
				System.out.println("\t-t <x>   use <x> threads to generate token");
				System.out.println("\t         (<x> should be the largest number of threads");
				System.out.println("\t         your system can execute in parallel. Example:");
				System.out.println("\t         set x=2 for a hyperthreading or dual-CPU system)");
				System.out.println("\nExamples:");
				System.out.println("\tyahct test 30");
				System.out.println("\tyahct -e -t 2 test 30");
				System.out.println("\tyahct 0:031216:test:ui0QIquZVuv check");
				return;
			}
			boolean est = false;
			boolean raw = false;
			int threadCount = 1;
			for (int i=0; i<args.length-2; i++) {
				if (args[i].equalsIgnoreCase("-r")) {
					raw = true;
				}
				if (args[i].equalsIgnoreCase("-e")) {
					est = true;
				}
				if (args[i].equalsIgnoreCase("-t")) {
					i++;
					threadCount = Integer.parseInt(args[i]);
				}
			}
			threadCount = Math.min(Math.max(1,threadCount),16);
			String prefix = args[args.length-2];
			if (args[args.length-1].equalsIgnoreCase("check")) {
				String token = prefix;
				String time = getHCTokenPart(prefix,1);
				String chal = getHCTokenPart(prefix,2);
				System.out.print("Token ["+token+"] is ");
				boolean valid = getHCTokenPart(prefix,0).equals("0") && time.length()>=6 && chal.length()>=1;
				if (valid) {
					valid = isTokenOK(chal,true,time,time,0,token);
				}
				if (!valid) {
					System.out.println("invalid.");
				} else {
					System.out.println("valid. ("+getTokenValue(token)+" bits)");
				}
				return;
			}
			int bits = Integer.parseInt(args[args.length-1]);
			if (bits>=24) est=true;
			if (!raw) prefix = prefixForChallange(prefix);
			if (est) {
				System.out.print("estimating cost factor ... ");
				float cf = estimateCostFactor(threadCount);
				float es = estimateCost(cf,bits);
				System.out.println("done.\n"+bits+"-bit-HC-token generation takes approx. "+humanReadableTime(es));
			}
			System.out.println("generating HashCash token ...");
			String token = "<invalid>";
			System.out.println("("+prefix+"???, threads="+threadCount+")");
			long time1 = System.currentTimeMillis();
			if (threadCount<2) {
				token = genRawToken(prefix,bits,new Random());
			} else {
				token = genRawToken(prefix,bits,threadCount);
			}
			long time2 = System.currentTimeMillis() - time1;
			System.out.println("\n\t"+token+"\n\t("+getTokenValue(token)+" bits, took "+humanReadableTime(time2/1000f)+")");
		} catch (NumberFormatException e) {
			System.out.println("error while parsing an integer argument");
		} finally {
			System.out.println();
		}
	}
}
