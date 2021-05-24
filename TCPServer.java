package pki;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
// import java.net.SocketException;

/**
 * The implementation of PKI server
 * that receives and decrypts the message sent from the client
 * @author Sua "Joshua" Lee
 * @version 17-11-2020
 */
public class TCPServer {
	// list of instance variables
	private ServerSocket serverSocket;
	private Socket socket;
	private InputStream inputStream;
	private int bufferSize;
	private int publicE;
	private int publicN;
	private PKIKey serverKey;
	
	/**
	 * The constructor of TCPServer object
	 * @param bufferSize The maximum size of the buffer
	 * @param serverKey The PKIKey for the server
	 * @param publicE The e value of the client's public key
	 * @param publicN The n value of the client's public key
	 */
	public TCPServer(int bufferSize, PKIKey serverKey, int publicE, int publicN)
	{
		try
		{
			this.bufferSize = bufferSize;
			serverSocket = new ServerSocket(1234);
			
			this.publicE = publicE;
			this.publicN = publicN;
			
			System.out.println("Waiting for client setup . . .");
			
			socket = serverSocket.accept();
			inputStream = socket.getInputStream();
			
			this.serverKey = serverKey;
			
			System.out.println("Connected!\n");
		}
		catch (IOException io)
		{
			io.printStackTrace();
		}
	}
	
	/**
	 * Receive and decrypt the message
	 * using the client's public key values
	 */
	public void authenticateAndPrint()
	{
		try
		{
			// receive message from the client
			byte[] readBuffer = new byte[bufferSize];
			inputStream.read(readBuffer);
			
			String message = new String(readBuffer, "UTF-8");
			
			System.out.println("Received the encrypted message:\n" 
					+ message + "\n");
			
			// decrypt the message
			long startTime = startFlag();
			char[] messageInChar = message.toCharArray();
			
			for (int i = 0; i < messageInChar.length; i++)
			{
				int decrypted = serverKey.decryptPublic(messageInChar[i], publicE, publicN);
				messageInChar[i] = (char) decrypted;
			}
			
			String decryptedMessage = String.valueOf(messageInChar);
			
			// remove paddings from the message
			int endOfMsgIndex = 0;
			
			while (endOfMsgIndex < decryptedMessage.length() && decryptedMessage.charAt(endOfMsgIndex) != '$')
			{
				endOfMsgIndex++;
			}
			
			String finalMessage = decryptedMessage.substring(0, endOfMsgIndex);
			
			long endTime = endFlag(startTime);
			System.out.println("Here's the decrypted message: \n" + finalMessage);
			
			System.out.println("Time spent: " + endTime + "\n");
		}
		catch (IOException io)
		{
			io.printStackTrace();
		}
	}
	
	/**
	 * Receive and decrypt the message
	 * using the server's private key values
	 */
	public void decryptAndPrint()
	{
		try
		{
			// receive message from the client
			byte[] readBuffer = new byte[bufferSize];
			inputStream.read(readBuffer);
			
			String message = new String(readBuffer, "UTF-8");
			
			System.out.println("Received the encrypted message:\n" 
					+ message + "\n");
			
			// decrypt the message
			long startTime = startFlag();
			char[] messageInChar = message.toCharArray();
			
			for (int i = 0; i < messageInChar.length; i++)
			{
				int decrypted = serverKey.decryptPrivate(messageInChar[i]);
				messageInChar[i] = (char) decrypted;
			}
			
			String decryptedMessage = String.valueOf(messageInChar);
			
			// remove paddings from the message
			int endOfMsgIndex = 0;
			
			while (endOfMsgIndex < decryptedMessage.length() && decryptedMessage.charAt(endOfMsgIndex) != '$')
			{
				endOfMsgIndex++;
			}
			
			String finalMessage = decryptedMessage.substring(0, endOfMsgIndex);
			
			long endTime = endFlag(startTime);
			System.out.println("Here's the decrypted message: \n" + finalMessage);
			
			System.out.println("Time spent: " + endTime + "\n");
		}
		catch (IOException io)
		{
			io.printStackTrace();
		}
	}
	
	/**
	 * Receive and decrypt the message
	 * using both authentication and signature methods
	 */
	public void decryptAndAuthenticate()
	{
		try
		{
			// receive message from the client
			byte[] readBuffer = new byte[bufferSize];
			inputStream.read(readBuffer);
			
			String message = new String(readBuffer, "UTF-8");
			
			System.out.println("Received the encrypted message:\n" 
					+ message + "\n");
			
			// decrypt the message
			long startTime = startFlag();
			char[] messageInChar = message.toCharArray();
			
			for (int i = 0; i < messageInChar.length; i++)
			{
				/*
				 * check if the n value of this object is
				 * larger than the value of the other's
				 */
				if (publicN < serverKey.getPublicN())
				{
					// if so, decrypt then authenticate
					int decrypted = serverKey.decryptPrivate(messageInChar[i]);
					decrypted = serverKey.decryptPublic(decrypted, publicE, publicN);
					messageInChar[i] = (char) decrypted;
				}
				else
				{
					// do the opposite otherwise
					int decrypted = serverKey.decryptPublic(messageInChar[i], publicE, publicN);
					decrypted = serverKey.decryptPrivate(decrypted);
					messageInChar[i] = (char) decrypted;
				}
			}
			
			String decryptedMessage = String.valueOf(messageInChar);
			
			// remove paddings from the message
			int endOfMsgIndex = 0;
			
			while (endOfMsgIndex < decryptedMessage.length() && decryptedMessage.charAt(endOfMsgIndex) != '$')
			{
				endOfMsgIndex++;
			}
			
			String finalMessage = decryptedMessage.substring(0, endOfMsgIndex);
			
			long endTime = endFlag(startTime);
			System.out.println("Here's the decrypted message: \n" + finalMessage);
			
			System.out.println("Time spent: " + endTime + "\n");
		}
		catch (IOException io)
		{
			io.printStackTrace();
		}
	}
	
	/**
	 * Mark the time when the decrypting started
	 * @return The time when the decrypting started
	 */
	private long startFlag()
	{
		return System.currentTimeMillis();
	}
	
	/**
	 * Mark the time when the decrypting ended,
	 * and return the overall time took to decrypt the message
	 * @param startTime The starting time of the decryption
	 * @return The total time spent to decrypt the message
	 */
	private long endFlag(long startTime)
	{
		long endTime = System.currentTimeMillis();
		
		return endTime - startTime;
	}
}
