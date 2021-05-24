package pki;

import java.util.Scanner;

/**
 * Driver class for TCPServer
 * @author Sua "Joshua" Lee
 * @version 17-11-2020
 */
public class PKIServerDriver {
	public static void main(String[] args)
	{
		Scanner sc = new Scanner(System.in);
		
		System.out.print("Please input the buffer size\n"
				+ "The buffer size must be identical with the one from the client: ");
		
		int bufferSize = sc.nextInt();
		sc.nextLine();
		
		// set up the server's PKI key
		System.out.print("Please input the value of p.\n"
				+ "The value of p should be prime number: ");
		byte p = sc.nextByte();
		sc.nextLine();
		
		System.out.println();
		
		System.out.print("Please input the value of q.\n"
				+ "The value of q should be prime number that is NOT equal to p: ");
		byte q = sc.nextByte();
		sc.nextLine();
		
		System.out.println();
		
		System.out.print("Please input the value of e.\n"
				+ "The value of e should be coprime to (p - 1)*(q - 1): ");
		byte e = sc.nextByte();
		sc.nextLine();
		
		System.out.println();
		
	    // create a client key based on the inputs
		PKIKey serverKey = new PKIKey(p, q, e);
		
		// inform the user about the PKIKey values
		System.out.println("Your public key pair is {"
				+ serverKey.getPublicE() + ", " + serverKey.getPublicN() + "}.");
		System.out.println("Share this value with the client.");
		
		System.out.println("Your private key pair is {"
				+ serverKey.getPrivateD() + ", " + serverKey.getPublicN() + "}.");
		System.out.println("Do NOT share this value with the client.");
		System.out.println();
		
		// prompt the user for the client's public key values
		System.out.print("Please input e value of the client's public key: ");
		
		int clientE = sc.nextInt();
		sc.nextLine();
		
		System.out.print("Please input n value of the client's public key: ");
		
		int clientN = sc.nextInt();
		sc.nextLine();
		
		System.out.println();
		
		// ask the user for the type of decryption
		boolean appropriateInput = false;
		int choice = 1;
		
		while (!appropriateInput)
		{
			System.out.println("Please choose the type of decryption."
					+ "The type MUST MATCH the one set by your client: \n"
					+ "\t 1 - Authentication\n"
					+ "\t 2 - Decryption\n"
					+ "\t 3 - Both");
			System.out.print("Input the appropriate number: ");
			choice = sc.nextInt();
			sc.nextLine();
			
			if (choice > 0 && choice < 4)
			{
				appropriateInput = true;
			}
			else
			{
				System.out.println("Cannot recognize input; try again.");
			}
		}
		
		TCPServer server = new TCPServer(bufferSize, serverKey, clientE, clientN);
		
		switch (choice) {
		case 1:
			server.authenticateAndPrint();
			break;
			
		case 2:
			server.decryptAndPrint();
			break;
			
		case 3:
			server.decryptAndAuthenticate();
			break;
		}
		
		sc.close();
	}
}
