import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Client {
	
	private static Message messageObj;
	private static String recipientHash;
	private static String userid;
	
	/*
	 * KEY STORAGE 
	 * -----------
	 * Assumed each user has local access to THEIR OWN private key & the public key of the INTENDED RECIPIENT
	 * 
	 */
	
	public static void main(String [] args) throws Exception {

		String host = args[0]; // hostname of server
		
		int port = Integer.parseInt(args[1]); // port of server
		
		userid = args[2]; // non-hashsed userid

		Socket s = new Socket(host, port);
		
		DataOutputStream dos = new DataOutputStream(s.getOutputStream());
		
		DataInputStream dis = new DataInputStream(s.getInputStream());
		
		recipientHash = Encrypter.generateUseridHash(userid);
		
		SecretKey key = Encrypter.generateKey();
		
		byte[] iv = Encrypter.generateIV();
		
		//Temp vals
		Scanner sc = new Scanner(System.in);
		String aLine = null;
		String recipient = null;
		String message = null;
		Date timestamp;
		List<Message> inbox = new ArrayList<>();
		
		if(s.isConnected()) {
			
			System.out.println("Connected to " + host + "\n");
			
			dos.writeUTF(recipientHash);
			
			int InboxSize = dis.readInt();
			
			System.out.println("You recieved " + InboxSize + " messages." + "\n");
			
			if(InboxSize > 0 ) {
				
				inbox.clear();
				
				ObjectInputStream inboxList = new ObjectInputStream(s.getInputStream());
				
				inbox = (List<Message>)inboxList.readObject();
				
				for(int i = 0;i<inbox.size(); i++) {
					
					Message msg = inbox.get(i);
					
					String senderID = null; //Used to obtain appropriate .pub file
					String dcrMessage = null;
					
					try {
						
						SecretKey secretKey = Decrypter.DecryptKey(userid, msg.key);
						
						byte[] txt = Decrypter.decryptMessage(msg.encryptedMsg, secretKey, msg.iv);
						
						String[] lines = new String(txt).split("\\n");
						
						senderID = lines[0];
						dcrMessage = lines[1];
						
					}catch(Exception e) { 
						
						System.out.println("ERR: " + e);
					}		
					
					if(VerifySignature(senderID, msg.signature, msg.encryptedMsg)) {
						
							System.out.println(senderID + "'s message:");
							System.out.println(dcrMessage);
							System.out.println(msg.timestamp + "\n");
						
					} else {
						
						System.out.println("Signature Failed");
					}
				}
			}
			
			String input = "";
			
			System.out.println("Do you want to send a message? [Y/N]");
			
			while(!input.equals("N")) {
				
				input = sc.nextLine();
				
				if(input.equals("Y") || input.equals("y")) {
					
					dos.writeUTF("Y"); //Send through value so that server can listen for Message Object
					
					System.out.println("Who do you want to send a message too?");
					
						recipient = sc.nextLine();
					
						dos.writeUTF(recipient);
					
					System.out.println("What do you want to send?");
					
						message = sc.nextLine();
					
						messageObj = new Message();
					
					timestamp = new Date();
					
					messageObj.timestamp = timestamp;
					
					messageObj.recipientHash = recipientHash;
					
					messageObj.iv = iv;
					
					byte[] encMsg = Encrypter.encryptMessage(userid, message, recipient, key, iv);
					
					messageObj.encryptedMsg = encMsg; //Sets both encKey and msg
					
					messageObj.signature = Encrypter.generateSignature(userid, encMsg);
					
					ObjectOutputStream sendMsg = new ObjectOutputStream(s.getOutputStream());
					
					sendMsg.writeObject(messageObj);
					
					System.out.println("Do you want to send a message? [Y/N]");
				} 
				else 
					
					System.out.println("Please enter a valid input [Y/N]");
			}
			System.out.println("Disconnecting client..");
			s.close();
		}
	}
	
	public static class Decrypter {
	
		private static byte[] decryptMessage(byte[] message, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, ClassNotFoundException, IOException {
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			
			byte[] output = cipher.doFinal(message);
			
			return output;
			
		}
		
		 private static SecretKey DecryptKey(String userid, byte[] key) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			
			File file = new File(Client.userid + ".prv");
			 
			FileInputStream keyfis = new FileInputStream(file);		
			
			ObjectInputStream object = new ObjectInputStream(keyfis);
			
			PrivateKey prvKey = (PrivateKey) object.readObject();
			
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			c.init(Cipher.DECRYPT_MODE, prvKey);
			
			byte[] output = key;
			
			byte [] decrypted_cipher = c.doFinal(output);
			
			SecretKey SecKey = new SecretKeySpec(decrypted_cipher, 0, decrypted_cipher.length, "AES");				
			
			return SecKey;
			
		}
	}

	private static boolean VerifySignature(String senderID, byte[] sig, byte[] message) throws NoSuchAlgorithmException, IOException, ClassNotFoundException, SignatureException, InvalidKeyException {
	
		Signature signature = Signature.getInstance("SHA1withRSA");
		
		File file = new File(senderID + ".pub");
		
		FileInputStream keyfis = new FileInputStream(file);		
		
		ObjectInputStream object = new ObjectInputStream(keyfis);
		
		PublicKey publicKey = (PublicKey) object.readObject();
		
		signature.initVerify(publicKey);
		
		signature.update(message);
		
		Boolean bool = signature.verify(sig);
		
		if(bool == true) {
			
			return true;
		
		} else {
		
			return false;
		
		}		
	}

	public static class Encrypter {
		
		private static byte[] encryptMessage(String userid, String message, String recipient, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, ClassNotFoundException, IOException {
			
			String encMsg = userid + "\n" + message;
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			
			messageObj.key = Encrypter.generateEncKey(recipient, key);
			
			byte[] output = cipher.doFinal(encMsg.getBytes("UTF-8"));
			
			return output;
			
			
		}
		 
		public static byte[] generateEncKey(String recipientID, SecretKey key) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, ClassNotFoundException {
			
			File file = new File(recipientID + ".pub");
			
			FileInputStream keyfis = new FileInputStream(file);		
			
			ObjectInputStream object = new ObjectInputStream(keyfis);
			
			PublicKey pubKey = (PublicKey) object.readObject();
			
			byte[] eKey = key.getEncoded();
			
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			c.init(Cipher.ENCRYPT_MODE, pubKey);
			
			byte[] output = c.doFinal(eKey);
			
			return output;
			
		}
		
		public static byte[] generateSignature(String user, byte[] message) throws NoSuchAlgorithmException, IOException, ClassNotFoundException, InvalidKeyException, SignatureException {
			
			Signature signature = Signature.getInstance("SHA1withRSA");
			
			File file = new File(userid + ".prv");
			
			FileInputStream keyfis = new FileInputStream(file);		
			
			ObjectInputStream object = new ObjectInputStream(keyfis);
				
			PrivateKey privateKey = (PrivateKey) object.readObject();
			
			signature.initSign(privateKey);
			
			signature.update(message);
			
			return signature.sign();

		}

		public static byte[] generateIV() {
			
			byte[] iv = new byte[16];
			
			SecureRandom random = new SecureRandom();
			
			random.nextBytes(iv);
			
			return iv;
			
		}
		
		private static SecretKey generateKey() throws NoSuchAlgorithmException {
			
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			
			kg.init(256);
			
			SecretKey key = kg.generateKey();
			
			return key;
			
		}
		
		
		private static String generateUseridHash(String userid) throws NoSuchAlgorithmException {
			
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			byte[] idBytes = userid.getBytes("UTF-8");
			
			byte[] output = md.digest(idBytes);
			
			return new String(output);
		}
		
	}
}

