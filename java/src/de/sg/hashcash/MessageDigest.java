/*
 * Created on 23.11.2003
 */
package de.sg.hashcash;

/**
 * @author Sebastian Gesemann
 */
public interface MessageDigest extends Cloneable
{
	public String getMDName();

	public Object clone() throws CloneNotSupportedException;

	public void reset();

	/**
	 * @return the digest size in bytes
	 */
	public int getDigestSize();

	/**
	 * @return the block size in bytes
	 */
	public int getBlockSize();

	/**
	 * updates the MessageDigest's state
	 * @param buf - byte array containing data
	 */
	public void update(byte[] buf);

	/**
	 * updates the MessageDigest's state
	 * @param buf - byte array containing data
	 * @param ofs - offset for data
	 * @param len - length of data
	 */
	public void update(byte[] buf, int ofs, int len);

	/**
	 * computes the message digest, stores it into the given array and resets the state
	 * @param digest - byte array for the digest to store in
	 * @param digOfs - offset, at which the message digest should be stored
	 */
	public void digest(byte[] dig, int digOfs);

	/**
	 * processes the last data block, stores the message digest into the given array
	 * and resets the state
	 * @param buf - byte array containing data
	 * @param ofs - offset for data
	 * @param len - length of data
	 * @param digest - byte array for the digest to store in
	 * @param digOfs - offset, at which the message digest should be stored
	 */
	public void digest(byte[] buf, int ofs, int len, byte[] digest, int digOfs);

	/**
	 * The state will be automatically reset after hash computation
	 * @return a new array containing the message digest
	 */
	public byte[] digest();

	/**
	 * The state will be automatically reset after hash computation
	 * @param buf - byte array containing data
	 * @param ofs - offset for data
	 * @param len - length of data
	 * @return a new array containing the message digest after processing
	 * the last given data block
	 */
	public byte[] digest(byte[] buf, int ofs, int len);
}
