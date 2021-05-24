package pki;

import java.util.Scanner;

public class CoprimeTester {
	public static void main(String[] args)
	{
		Scanner sc = new Scanner(System.in);

		String test = sc.nextLine();
		
		char[] testInChars = test.toCharArray();
		
		for (int i = 0; i < test.length(); i++)
		{
			testInChars[i] = (char) (3 + testInChars[i]);
		}
		
		System.out.println(String.valueOf(testInChars));
		sc.close();
	}
	
	public static boolean checkIfCoprime(int first, int second)
	{
		boolean result = true;
		boolean testFailed = false;
		
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
}
