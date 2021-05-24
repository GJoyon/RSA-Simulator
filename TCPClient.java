package pki;

import java.io.*;
import java.net.Socket;
import java.util.Random;

/**
 * The implementation of PKI client
 * that encrypts and sends the message given by its user
 * @author Sua "Joshua" Lee
 * @version 17-11-2020
 */
public class TCPClient {
	// list of instances to be used
	private Socket socket;
	private OutputStream outputStream;
	private byte[] buffer;
	private int bufferSize;
	private int publicE;
	private int publicN;
	private PKIKey clientKey;
	private Random rand;
	
	/**
	 * Constructor of the class TCP client
	 * @param targetAddress The address of the target (server)
	 * @param bufferSize The size of the given buffer
	 * @param clientKey The PKIKey for client
	 * @param publicE The e value of the server's public key
	 * @param publicN The n value of the server's public key
	 */
	public TCPClient(String targetAddress, int bufferSize, PKIKey clientKey, int publicE, int publicN)
	{
		try
		{
			socket = new Socket(targetAddress, 1234);
			outputStream = socket.getOutputStream();
			buffer = new byte[bufferSize];
			this.bufferSize = bufferSize;
			this.clientKey = clientKey;
			this.publicE = publicE;
			this.publicN = publicN;
			rand = new Random();
		}
		catch (IOException io)
		{
			io.printStackTrace();
		}
	}
	
	/**
	 * Send a message that is encrypted using authentication process
	 * @param message The given message
	 */
	public void authenticateAndSend(String message)
	{
		if (socket.isConnected())
		{
			try
			{
				/*
				 * the character '$' serves as a mark that lets the server know that
				 * any characters following '$' do not belong to the original message 
				 */
				long startTime = startFlag();
				String messageMarked = message.concat("$");
				char[] messageInChars = messageMarked.toCharArray();
	
				// encrypt the message using the client's private key values
				for (int i = 0; i < messageInChars.length; i++)
				{
					int encrypted = clientKey.encryptPrivate(messageInChars[i]);
					messageInChars[i] = (char) encrypted;
				}
				
				String encryptedMessage = String.valueOf(messageInChars);
				
				byte[] msgInBytes = encryptedMessage.getBytes("UTF-8");
				System.arraycopy(msgInBytes, 0, buffer, 0, msgInBytes.length);
				
				// fill the empty spaces in the buffer with paddings
				if (msgInBytes.length < bufferSize)
				{
					for (int i = msgInBytes.length; i < bufferSize; i++)
					{
						buffer[i] = (byte) rand.nextInt(128);
					}
				}
				
				long endTime = endFlag(startTime);
				System.out.println("The message has been encrypted as follows: \n"
						+ new String(buffer, "UTF-8"));
				
				System.out.println("Time spent: " + endTime + "\n");
				
				outputStream.write(buffer);
			}
			catch (IOException io)
			{
				io.printStackTrace();
			}
		}
	}
	
	/**
	 * Send a message that is encrypted using signature (i.e. encryption) process
	 * @param message The given message
	 */
	public void encryptAndSend(String message)
	{
		if (socket.isConnected())
		{
			try
			{
				/*
				 * the character '$' serves as a mark that lets the server know that
				 * any characters following '$' do not belong to the original message 
				 */
				long startTime = startFlag();
				String messageMarked = message.concat("$");
				char[] messageInChars = messageMarked.toCharArray();
				
				// encrypt the message using the server's public key values
				for (int i = 0; i < messageInChars.length; i++)
				{
					int encrypted = clientKey.encryptPublic(messageInChars[i], publicE, publicN);
					messageInChars[i] = (char) encrypted;
				}
				
				String encryptedMessage = String.valueOf(messageInChars);
				
				byte[] msgInBytes = encryptedMessage.getBytes("UTF-8");
				System.arraycopy(msgInBytes, 0, buffer, 0, msgInBytes.length);
				
				// fill the empty spaces in the buffer with paddings;
				if (msgInBytes.length < bufferSize)
				{
					for (int i = msgInBytes.length; i < bufferSize; i++)
					{
						buffer[i] = (byte) rand.nextInt(128);
					}
				}
				
				long endTime = endFlag(startTime);
				System.out.println("The message has been encrypted as follows: \n"
						+ new String(buffer, "UTF-8"));
				
				System.out.println("Time spent: " + endTime + "\n");
				
				outputStream.write(buffer);
			}
			catch (IOException io)
			{
				io.printStackTrace();
			}
		}
	}
	
	/**
	 * Send a message that is encrypted using both authentication and encryption processes
	 * @param message The given message
	 */
	public void encryptAndAuthenticate(String message)
	{
		if (socket.isConnected())
		{
			try
			{
				/*
				 * the character '$' serves as a mark that lets the server know that
				 * any characters following '$' do not belong to the original message 
				 */
				long startTime = startFlag();
				String messageMarked = message.concat("$");
				char[] messageInChars = messageMarked.toCharArray();
				
				// encrypt the message
				for (int i = 0; i < messageInChars.length; i++)
				{
					// compare the n value of this object against the other's
					if (clientKey.getPublicN() < publicN)
					{
						/*
						 *  if the n value of this object is smaller,
						 *  authenticate first, and then encrypt
						 */
						int encrypted = clientKey.encryptPrivate(messageInChars[i]);
						encrypted = clientKey.encryptPublic(encrypted, publicE, publicN);
						messageInChars[i] = (char) encrypted;
					}
					else
					{
						// encrypt first and then authenticate otherwise
						int encrypted = clientKey.encryptPublic(messageInChars[i], publicE, publicN);
						encrypted = clientKey.encryptPrivate(encrypted);
						messageInChars[i] = (char) encrypted;
					}
				}
				
				String encryptedMessage = String.valueOf(messageInChars);
				
				byte[] msgInBytes = encryptedMessage.getBytes("UTF-8");
				System.arraycopy(msgInBytes, 0, buffer, 0, msgInBytes.length);
				
				// fill the empty spaces in the buffer with paddings;
				if (msgInBytes.length < bufferSize)
				{
					for (int i = msgInBytes.length; i < bufferSize; i++)
					{
						buffer[i] = (byte) rand.nextInt(128);
					}
				}
				
				long endTime = endFlag(startTime);
				System.out.println("The message has been encrypted as follows: \n"
						+ new String(buffer, "UTF-8"));
				
				System.out.println("Time spent: " + endTime + "\n");
				
				outputStream.write(buffer);
			}
			catch (IOException io)
			{
				io.printStackTrace();
			}
		}
	}
	
	/**
	 * Mark the time when the encrypting started
	 * @return The time when the encrypting started
	 */
	private long startFlag()
	{
		return System.currentTimeMillis();
	}
	
	/**
	 * Mark the time when the encrypting ended,
	 * and return the overall time took to encrypt the message
	 * @param startTime The starting time of the encryption
	 * @return The total time spent to encrypt the message
	 */
	private long endFlag(long startTime)
	{
		long endTime = System.currentTimeMillis();
		
		return endTime - startTime;
	}
}
