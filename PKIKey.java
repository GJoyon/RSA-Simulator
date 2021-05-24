package pki;

import java.util.InputMismatchException;

/**
 * The Java implementation of public key infrastructure
 * 
 * @author Sua "Joshua" Lee
 * @version 17-11-2020
 */
public class PKIKey {
	// list of instance fields
	private int n;
	private int e;
	private int nPhi;
	private int d;
	
	/**
	 * Constructor for PKIKey.
	 * p and q must be prime numbers that are not equal to each other.
	 * The user also needs to choose e that is coprime to \Phi(n)
	 * @param p The value of p
	 * @param q The value of q
	 * @param e The value of e
	 */
	public PKIKey(int p, int q, int e)
	{
		// check if the given values match the conditions of the PKIKey
		int potentialNPhi = (p - 1) * (q - 1);
	
		if (!checkIfPrime(p) || !checkIfPrime(q) || p == q || !checkIfCoprime(e, potentialNPhi))
		{
			throw new InputMismatchException();
		}
		
		// set the values for PKIKey
		n = (p * q);
		nPhi = ((p - 1) * (q - 1));
		this.e = e;
		d = findInverseMod(this.e, nPhi);
	}
	
	/**
	 * Encrypt a given message in byte using the recipient's public key pair {e, n}
	 * @param m The given message
	 * @param publicE The e value of the recipient's public key pair
	 * @param publicN the n value of the recipient's public key pair
	 * @return The encrypted message
	 */
	public int encryptPublic (int m, int publicE, int publicN)
	{
		// the given m should be less than n
		if (m >= publicN)
		{
			throw new InputMismatchException();
		}
		
		// now calculate m^e mod n
		double intermediateMod = m % publicN;
		
		for (int i = 1; i < publicE; i++)
		{
			intermediateMod *= m % publicN;
			
			if (intermediateMod >= publicN)
			{
				intermediateMod = intermediateMod % publicN;
			}
		}
		
		double finalMod = intermediateMod % publicN;
		
		return (int) finalMod;
	}
	
	/**
	 * Encrypt the given message in byte using the sender's private key
	 * @param m The given message
	 * @return The encrypted message
	 */
	public int encryptPrivate (int m)
	{
		// the given m should be less than n
		if (m >= n)
		{
			throw new InputMismatchException();
		}
		
		// now calculate m^d mod n
		double intermediateMod = m % n;
		
		for (int i = 1; i < d; i++)
		{
			intermediateMod *= m % n;
			
			if (intermediateMod >= n)
			{
				intermediateMod = intermediateMod % n;
			}
		}
		
		double finalMod = intermediateMod % n;
		
		return (int) finalMod;
	}
	
	/**
	 * Decrypt a given message using the sender's public key pair {e, n}
	 * @param c The given encrypted message
	 * @param publicE The e value of the sender's public key pair {e, n}
	 * @param publicN The n value of the sender's public key pair {e, n}
	 * @return The decrypted message
	 */
	public int decryptPublic (int c, int publicE, int publicN)
	{
		/*
		 *  there's no need to check if the resulting m is less than n;
		 *  just proceed to the decryption process
		 */
		double intermediateMod = c % publicN;
		
		for (int i = 1; i < publicE; i++)
		{
			intermediateMod *= c % publicN;
			
			if (intermediateMod >= publicN)
			{
				intermediateMod = intermediateMod % publicN;
			}
		}
		
		double finalMod = intermediateMod % publicN;
		
		return (int) finalMod;
	}
	
	/**
	 * Decrypt a given message in byte using the recipient's private key
	 * @param c The given encrypted message
	 * @return The decrypted message
	 */
	public int decryptPrivate (int c)
	{
		/*
		 *  there's no need to check if the resulting m is less than n;
		 *  just proceed to the decryption process
		 */
		double intermediateMod = c % n;
		
		for (int i = 1; i < d; i++)
		{
			intermediateMod *= c % n;
			
			if (intermediateMod >= n)
			{
				intermediateMod = intermediateMod % n;
			}
		}
		
		double finalMod = intermediateMod % n;
		
		return (int) finalMod;
	}
	
	/**
	 * Get the e value of the public key pair {e, n}
	 * @return The e value of the public key pair {e, n}
	 */
	public int getPublicE()
	{
		return e;
	}
	
	/**
	 * Get the d value of the private key pair {d, n}
	 * @return The d value of the private key pair {d, n}
	 */
	public int getPrivateD()
	{
		return d;
	}
	
	/**
	 * Get the n value of the public key pair {e, n}
	 * @return The n value of the public key pair {e, n}
	 */
	public int getPublicN()
	{
		return n;
	}
	
	/**
	 * Check if the given input is positive and prime or not
	 * @param input The given input
	 * @return Whether the given input is prime
	 */
	private boolean checkIfPrime(int input)
	{
		boolean result = true;
		
		// do not count 1 or less
		if (input <= 1)
		{
			result = false;
		}
		// 2 is prime; no need to check
		// start with 3
		else if (input > 2)
		{
			boolean testFailed = false;
			
			for (int factor = 2; !testFailed && factor < input; factor++)
			{
				if (input % factor == 0)
				{
					result = false;
					testFailed = true;
				}
			}
		}
		
		return result;
	}
	
	/**
	 * Check if given two inputs are relatively prime to each other
	 * @param first The first input
	 * @param second The second input
	 * @return Whether the two inputs are relatively prime
	 */
	private boolean checkIfCoprime(int first, int second)
	{
		boolean result = true;
		boolean testFailed = false;
		
		// check if gcd(first, second) = 1
		for (int factor = 2; !testFailed && factor <= first && factor <= second; factor++)
		{
			if (first % factor == 0 && second % factor == 0)
			{
				result = false;
				testFailed = true;
			}
		}
		
		return result;
	}
	
	/**
	 * Find the integer value i such that (a * i) mod n = 1 using brute force method
	 * @param input The value of a
	 * @param modValue The value of n
	 * @return The value of i
	 */
	private int findInverseMod(int input, int modValue)
	{
		int inverse = 1;
		
		while ((input * inverse) % modValue != 1)
		{
			inverse++;
		}
		
		return inverse;
	}
}
