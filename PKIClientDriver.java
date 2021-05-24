package pki;

import java.util.Scanner;

/**
 * The driver class for TCPClient
 * @author Sua "Joshua" Lee
 * @version 17-11-2020
 */
public class PKIClientDriver {
	public static void main(String[] args)
	{
		Scanner sc = new Scanner(System.in);
		
		System.out.print("Please input the target address: ");
		String address = sc.nextLine();
		
		System.out.print("Please input the buffer size: ");
		
		int bufferSize = sc.nextInt();
		sc.nextLine();
		System.out.println();
		
		// read the values of p, q, and e from user
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
		PKIKey clientKey = new PKIKey(p, q, e);
		
		// inform the user about the PKIKey values
		System.out.println("Your public key pair is {"
				+ clientKey.getPublicE() + ", " + clientKey.getPublicN() + "}.");
		System.out.println("Share this value with the server.");
		
		System.out.println("Your private key pair is {"
				+ clientKey.getPrivateD() + ", " + clientKey.getPublicN() + "}.");
		System.out.println("Do NOT share this value with the server.");
		System.out.println();
		
		// prompt the user for the server's public key values
		System.out.print("Please input e value of the server's public key: ");
		
		int serverE = sc.nextInt();
		sc.nextLine();
		
		System.out.print("Please input n value of the server's public key: ");
		
		int serverN = sc.nextInt();
		sc.nextLine();
		System.out.println();
		
		// ask the user for the type of encryption
		boolean appropriateInput = false;
		int choice = 1;
		
		while (!appropriateInput)
		{
			System.out.println("Please choose the type of encryption you wish: \n"
					+ "\t 1 - Authentication\n"
					+ "\t 2 - Encryption\n"
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
		
		// time to read the message
		System.out.print("Please input the message: ");
		String message = sc.nextLine();
		
		TCPClient theClient = new TCPClient(address, bufferSize, clientKey, serverE, serverN);
		
		switch (choice) {
		case 1:
			theClient.authenticateAndSend(message);
			break;
			
		case 2:
			theClient.encryptAndSend(message);
			break;
			
		case 3:
			theClient.encryptAndAuthenticate(message);
			break;
		}
		
		System.out.println("Message sent");
		
		sc.close();
	}
}
