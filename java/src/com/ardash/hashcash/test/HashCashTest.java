package com.ardash.hashcash.test;

import static org.junit.Assert.fail;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class HashCashTest {

	@Test
	public void test() throws NoSuchAlgorithmException, InterruptedException {
		//HashCash hc = new HashCash("")
		String h =de.sg.hashcash.HashCash.genRawToken("aa", 20, 1);
		System.out.println(h);
//		hc.estimateTime(value)
		fail("Not yet implemented");
	}

}
