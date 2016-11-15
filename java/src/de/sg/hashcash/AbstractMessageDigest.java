/*
 * Created on 23.11.2003
 */
package de.sg.hashcash;

/**
 * @author Sebastian Gesemann
 */
public abstract class AbstractMessageDigest implements MessageDigest
{
	private byte[] buffer = new byte[getBlockSize()];
	private int bufPos = 0;

	public final void reset() {
		resetInternal();
	}	

	public final void update(byte[] buf) {
		update(buf,0,buf.length);
	}

	public final void update(byte[] buf, int ofs, int len) {
		int bs = getBlockSize();
		int ch;
		while (len>0) {
			ch = Math.min(len,bs-bufPos);
			if (bufPos>0 || (bufPos+ch<bs)) {
				System.arraycopy(buf,ofs,buffer,bufPos,ch);
				bufPos+=ch;
				ofs+=ch;
				len-=ch;
				if (bufPos==bs) {
					processInternal(buffer,0);
					bufPos = 0;
				}
			} else {
				processInternal(buf,ofs);
				ofs+=bs;
				len-=bs;
			}
		}
	}

	public final void digest(byte[] dig, int digOfs) {
		processFinalInternal(buffer,0,bufPos,dig,digOfs);
		bufPos=0;
		resetInternal();
	}

	public final void digest(byte[] buf, int ofs, int len, byte[] digest, int digOfs) {
		update(buf,ofs,len);
		digest(digest,digOfs);
	}

	public final byte[] digest() {
		byte[] dig = new byte[getDigestSize()];
		digest(dig,0);
		return dig;
	}

	public final byte[] digest(byte[] buf, int ofs, int len) {
		update(buf,ofs,len);
		return digest();
	}

	/**
	 * resets the internal state
	 */
	protected abstract void resetInternal();

	/**
	 * @param buf
	 * @param ofs
	 */
	protected abstract void processInternal(byte[] buf, int ofs);

	/**
	 * @param buf
	 * @param bufOfs
	 * @param len - must be within 0..getMaxFinalBlockSize()
	 * @param digest - the byte array to store the digest in
	 * @param digOfs
	 */
	protected abstract void processFinalInternal(byte[] buf, int bufOfs, int len, byte[] digest, int digOfs);

	public Object clone() throws CloneNotSupportedException {
		AbstractMessageDigest amd = (AbstractMessageDigest)(super.clone());
		amd.buffer = new byte[this.buffer.length];
		System.arraycopy(this.buffer,0,amd.buffer,0,this.buffer.length);
		return amd;
	}
}
