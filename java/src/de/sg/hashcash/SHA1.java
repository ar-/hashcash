/*
 * Created on 13.12.2003
 */
package de.sg.hashcash;

/**
 * @author Sebastian Gesemann
 */
public final class SHA1 extends StandardPaddingDigest
{
	public int getBlockSize() { return 64; } // 512 bit blocks
	protected int getLenCounterSize() { return 8; } // 64 bit length counter
	public int getDigestSize() { return 20; } // 160 bit message digest
	public final String getMDName() { return "SHA-1"; }

	private static final int WORDS = 80;

	private int aa,bb,cc,dd,ee;
	private int[] ww = new int[WORDS];

	{
		resetInternal2();
	}

	protected void resetInternal2() {
		aa = 0x67452301;
		bb = 0xefcdab89;
		cc = 0x98badcfe;
		dd = 0x10325476;
		ee = 0xc3d2e1f0;
	}

	protected void processInternal2(byte[] buf, int ofs) {
		int tmp;
		for (int o=0,i=ofs; o<16;)
			ww[o++] = (buf[i++] << 24) | ((buf[i++] & 0xFF) << 16) | ((buf[i++] & 0xFF) << 8) | (buf[i++] & 0xFF);
		for (int i=16; i<WORDS; i++) {
			tmp = ww[i-3] ^ ww[i-8] ^ ww[i-14] ^ ww[i-16];
			ww[i] = (tmp << 1) | (tmp >>> 31);
		}
		int a=aa, b=bb, c=cc, d=dd, e=ee;
		for (int i=0; i<20; i++) {
			tmp = ((a << 5) | (a >>> (27))) + ((b & c) ^ (~b & d)) + e + 0x5a827999 + ww[i];
			e = d; d = c;
			c = (b << 30) | (b >>> 2);
			b = a; a = tmp;
		}
		for (int i=20; i<40; i++) {
			tmp = ((a << 5) | (a >>> (27))) + (b ^ c ^ d) + e + 0x6ed9eba1 + ww[i];
			e = d; d = c;
			c = (b << 30) | (b >>> 2);
			b = a; a = tmp;
		}
		for (int i=40; i<60; i++) {
			tmp = ((a << 5) | (a >>> (27))) + ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8f1bbcdc + ww[i];
			e = d; d = c;
			c = (b << 30) | (b >>> 2);
			b = a; a = tmp;
		}
		for (int i=60; i<80; i++) {
			tmp = ((a << 5) | (a >>> (27))) + (b ^ c ^ d) + e + 0xca62c1d6 + ww[i];
			e = d; d = c;
			c = (b << 30) | (b >>> 2);
			b = a; a = tmp;
		}
		aa += a;
		bb += b;
		cc += c;
		dd += d;
		ee += e;
	}

	protected void storeHashState(byte[] buf, int ofs) {
		buf[ofs   ] = (byte)(aa >>> 24);
		buf[ofs+ 1] = (byte)(aa >>> 16);
		buf[ofs+ 2] = (byte)(aa >>> 8);
		buf[ofs+ 3] = (byte) aa;
		buf[ofs+ 4] = (byte)(bb >>> 24);
		buf[ofs+ 5] = (byte)(bb >>> 16);
		buf[ofs+ 6] = (byte)(bb >>> 8);
		buf[ofs+ 7] = (byte) bb;
		buf[ofs+ 8] = (byte)(cc >>> 24);
		buf[ofs+ 9] = (byte)(cc >>> 16);
		buf[ofs+10] = (byte)(cc >>> 8);
		buf[ofs+11] = (byte) cc;
		buf[ofs+12] = (byte)(dd >>> 24);
		buf[ofs+13] = (byte)(dd >>> 16);
		buf[ofs+14] = (byte)(dd >>> 8);
		buf[ofs+15] = (byte) dd;
		buf[ofs+16] = (byte)(ee >>> 24);
		buf[ofs+17] = (byte)(ee >>> 16);
		buf[ofs+18] = (byte)(ee >>> 8);
		buf[ofs+19] = (byte) ee;
	}

	public Object clone() throws CloneNotSupportedException {
		SHA1 sha1 = (SHA1)super.clone();
		sha1.ww = new int[WORDS];
		return sha1;
	}
}
