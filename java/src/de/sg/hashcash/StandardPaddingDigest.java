/*
 * Created on 13.12.2003
 */
package de.sg.hashcash;

/**
 * @author Sebastian Gesemann
 */
public abstract class StandardPaddingDigest extends AbstractMessageDigest
{
	private final int bytesPerCounter = getLenCounterSize();
	private final int bytesPerBlock = getBlockSize();
	private final int bitsPerBlock = bytesPerBlock*8;
	private byte[] lenCounter = new byte[bytesPerCounter];

	private final void incCounter(int bits) {
		int tmp;
		for(int o=lenCounter.length-1; bits>0 && o>=0; o--) {
			tmp = (lenCounter[o] & 0xFF) + (bits & 0xFF);
			lenCounter[o] = (byte)tmp;
			bits = (bits >>> 8) + (tmp >>> 8);
		} 
	}

	protected final void resetInternal() {
		for (int i=0; i<lenCounter.length; i++)
			lenCounter[i] = (byte)0;
		resetInternal2();
	}

	protected abstract void resetInternal2();

	protected final void processInternal(byte[] buf, int ofs) {
		processInternal2(buf,ofs);
		incCounter(bitsPerBlock);
	}

	protected abstract void processInternal2(byte[] buf, int ofs);

	protected final void processFinalInternal(byte[] buf, int bufOfs, int len, byte[] digest, int digOfs) {
		byte[] chunk = new byte[bytesPerBlock];
		System.arraycopy(buf,bufOfs,chunk,0,len);
		incCounter(len << 3);
		boolean finalbit;
		if (finalbit=(len<bytesPerBlock)) {
			chunk[len++] = (byte)0x80;
		}
		if (bytesPerBlock-len<bytesPerCounter) {
			processInternal2(chunk,0);
			for (int i=0; i<bytesPerBlock; i++)
				chunk[i] = 0;
			if (!finalbit) {
				chunk[0] = (byte)0x80;
			}
		}
		System.arraycopy(lenCounter,0,chunk,bytesPerBlock-bytesPerCounter,bytesPerCounter);
		processInternal2(chunk,0);
		storeHashState(digest,digOfs);
	}

	protected abstract void storeHashState(byte[] buf, int ofs);

	protected abstract int getLenCounterSize();

	public Object clone() throws CloneNotSupportedException {
		StandardPaddingDigest spd = (StandardPaddingDigest)super.clone();
		spd.lenCounter = new byte[bytesPerCounter];
		System.arraycopy(this.lenCounter,0,spd.lenCounter,0,bytesPerCounter);
		return spd;
	}
}
