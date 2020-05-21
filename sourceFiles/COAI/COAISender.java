package COAI;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
 

public class COAISender {
	
	public COAISender(String[] args) {
		cOAISender(args);
	}

	public static void main(String[] args) {
		new COAISender(args); 
	}


	private void cOAISender(String[] args) {
		// TODO Auto-generated method stub
		//./lab3 CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg
		if(args.length != 9) {
			System.out.println("Error in parameters");
			System.exit(0);
		}  
		String sender = args[2];
		String receiver = args[3];
		String emailInputFile = args[4]; //input plain text fichier (in ASCII format) 
		String emailOutputFile = args[5]; //output of the encryption algorithms (in binary format)  
		String digestAlg = args[6]; //sha sha3
		String encryAlg = args[7]; //Aes Des
		int RSAKeySize = Integer.parseInt(args[8]);//1024 or 2048
		
		String message = getMessage(emailInputFile);
		System.out.println("Message to send : "+message);
		
		SecretKey kh = generateKey(encryAlg); 
		
		String hash = generateHash(message, kh, digestAlg);
		System.out.println("Hash of the message : "+hash);
		
		Map<String, String> privateA = getPrivateKey(sender);
		String privateKeyA = "";
		String mudulus = "";
		for (Entry<String, String> entry : privateA.entrySet()) {
			privateKeyA = entry.getKey();
			mudulus = entry.getValue(); 
	     }
		System.out.println("Private Key Sender : "+privateKeyA+"\nModulus Sender : "+mudulus);
		
		byte[] cipherHashMessage = crypteHash(privateKeyA, mudulus, hash, RSAKeySize);
		
		
		SecretKey ks = generateKey(encryAlg); 
		System.out.println("ks : "+ks.getEncoded());
		
		Map<byte[], byte[]> cripteReturn = crypteMessage(ks, cipherHashMessage, message, encryAlg);
		byte[] cipherCryptedWithKs = null;
		byte[] iv = null;
		for (Entry<byte[], byte[]> entry : cripteReturn .entrySet()) {
			cipherCryptedWithKs = entry.getKey();
			iv = entry.getValue(); 
	    }
		
		Map<String, String> infosRecevier = getKeyReceiver(receiver);
		String keyPublicB = "";
		String mudulusB = "";
		for (Entry<String, String> entry : infosRecevier .entrySet()) {
			keyPublicB = entry.getKey();
			mudulusB = entry.getValue(); 
	    }
		
		System.out.println("Key public Receiver : " +keyPublicB);
		System.out.println("Key mudulus Receiver : " +mudulusB);
		byte[] cipherTextKeys = crypteKs(keyPublicB, mudulusB, ks, kh, iv);
		
		writeInfosInFile(emailOutputFile, cipherTextKeys, cipherCryptedWithKs); 

	}
	
	private static void writeInfosInFile(String emailOutputFile, byte[] cipherTextKeys, byte[] cipherCryptedWithKs) {
		// TODO Auto-generated method stub
		try {  
			String cipherTextMssg = Base64.getEncoder().encodeToString(cipherCryptedWithKs); 
			String cipherTextkeys = Base64.getEncoder().encodeToString(cipherTextKeys);  
			PrintWriter writer = new PrintWriter(emailOutputFile); 
		    writer.println(cipherTextkeys); 
		    writer.println(cipherTextMssg); 
		    writer.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] crypteKs(String keyPublicB, String mudulusB, SecretKey ks, SecretKey kh, byte[] iv) {
		// TODO Auto-generated method stub
		String encodedKeyS = Base64.getEncoder().encodeToString(ks.getEncoded());
		String encodedKeyH = Base64.getEncoder().encodeToString(kh.getEncoded());
		String encodedIv = Base64.getEncoder().encodeToString(iv);
		String parameters = encodedKeyS + "||" + encodedKeyH + "||" +encodedIv;
		BigInteger KeyB = new BigInteger(keyPublicB);
		BigInteger mudulus = new BigInteger(mudulusB);  
		byte[] ciphertext = crypt(parameters, KeyB, mudulus);  
		return ciphertext; 
	}

	private static Map<String, String> getKeyReceiver(String receiver) {
		// TODO Auto-generated method stub
		String keyPuB = "";
		String modulus = "";
		 try {
		    BufferedReader reader = new BufferedReader(new FileReader("user_pub_keylen.txt")); 
		    String line = "";
		    while ((line = reader.readLine()) != null) {
		    	if(line.contains(receiver)) {
		    		line = reader.readLine();
		    		line = reader.readLine();
		    		modulus = (String) line.subSequence(11, line.length());
		    		line = reader.readLine();
		    		keyPuB = (String) line.subSequence(19, line.length()); 
		    	} 
		    }
		    reader.close();
		    return Map.of(keyPuB, modulus);
		  } catch (Exception e){ 
		    e.printStackTrace();
		    return null;
		  }  
	}

	private static Map<byte[], byte[]> crypteMessage(SecretKey ks, byte[] cipherHashMessage, String message,
			String encryAlg) {
		// TODO Auto-generated method stub
		try {
			// Create the cipher, séparer pour DES
			String cipherHashMessageSafe = Base64.getEncoder().encodeToString(cipherHashMessage);
			String plaintext = cipherHashMessageSafe + "||" + message;
			Cipher cipher = null;
			if(encryAlg.equals("aes-256-cbc")) cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			else if(encryAlg.equals("des-ede3-cbc")) cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			else System.out.println("Error in parameters encryAlg");
		    // Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, ks); 
		    // Our cleartext
		    byte[] cleartext = plaintext.getBytes();  
		    // Encrypt the cleartext
		    byte[] ciphertext = cipher.doFinal(cleartext); 
		    byte[] encodedParams = cipher.getParameters().getEncoded();
		    return Map.of(ciphertext, encodedParams);
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}  
	}

	private static byte[] addOneByte(byte[] input) {
	    byte[] result = new byte[input.length+1];
	    result[0] = 1;
	    for (int i = 0; i < input.length; i++) {
	      result[i+1] = input[i];
	    }
	    return result;
	  }
	
	private static BigInteger crypt(BigInteger plaintext, BigInteger exponent, BigInteger mudulus) {
	    return plaintext.modPow(exponent, mudulus);
	  }
	  
	
	public static byte[] crypt(byte[] plaintext, BigInteger exponent, BigInteger mudulus) {
	    return crypt(new BigInteger(addOneByte(plaintext)), exponent, mudulus).toByteArray();
	  }
	  
	    
	  public static byte[] crypt(String plaintext, BigInteger exponent, BigInteger mudulus) {
	    return crypt(plaintext.getBytes(), exponent, mudulus);
	  }
	
	private static byte[] crypteHash(String privateKeyA, String mudulus, String hash, int RSAKeySize) {
		// TODO Auto-generated method stub
		BigInteger KeyA = new BigInteger(privateKeyA);
		BigInteger modulus = new BigInteger(mudulus);   
		if(RSAKeySize == 1024) hash = (new StringBuilder(hash)).deleteCharAt(hash.length()-1).toString();
		byte[] ciphertext = crypt(hash, KeyA, modulus);  
		return ciphertext;  
	}

	private static Map<String, String> getPrivateKey(String sender) {
		// TODO Auto-generated method stub 
		String keyPrB = "";
		String modulus = "";
		 try
		  {
		    BufferedReader reader = new BufferedReader(new FileReader("user_priv_keylen.txt")); 
		    String line = "";
		    while ((line = reader.readLine()) != null) {
		    	if(line.contains(sender)) {
		    		line = reader.readLine();
		    		line = reader.readLine();
		    		modulus = (String) line.subSequence(11, line.length());
		    		line = reader.readLine();
		    		keyPrB = (String) line.subSequence(20, line.length()); 
		    	} 
		    }
		    reader.close();
		    return Map.of(keyPrB, modulus);
		  } catch (Exception e) { 
		    e.printStackTrace();
		    return null;
		  }
	}

	private static String generateHash(String message, SecretKey kh, String digestAlg) {
		// TODO Auto-generated method stub 
	    try {
	    	String khSafe =  Base64.getEncoder().encodeToString(kh.getEncoded()); 
	    	String plaintext = khSafe + "||" + message;
	        MessageDigest md = null;
	        if(digestAlg.equals("sha512")) md = MessageDigest.getInstance("SHA-512"); 
	        else if(digestAlg.equals("sha3-512")) md = MessageDigest.getInstance("SHA3-512"); 
	        else System.out.println("Error in the digest Algorithm");
	         
	        byte[] bytes = md.digest(plaintext.getBytes(StandardCharsets.UTF_8));
	        StringBuilder sb = new StringBuilder();
	        for(int i=0; i< bytes.length ;i++){
	            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
	        } 
	        return sb.toString();  
	    } catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	        return null;
	    } 
	}

	private static SecretKey generateKey(String encryAlg) {
		try {
			KeyGenerator keygen = null; 
			if(encryAlg.equals("aes-256-cbc")) keygen = KeyGenerator.getInstance("AES");
			else if(encryAlg.equals("des-ede3-cbc")) keygen = KeyGenerator.getInstance("DES");
		    SecretKey key = keygen.generateKey(); 
		    return key;
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static String getMessage(String emailInputFile) {
		// TODO Auto-generated method stub
		 String message = "";
		 try {
		    BufferedReader reader = new BufferedReader(new FileReader(emailInputFile));
		    String line = reader.readLine();
		    message += line;
		    while ((line = reader.readLine()) != null) message += "\n" + line; 
		    reader.close();
		    return message;
		  } catch (Exception e) { 
		    e.printStackTrace();
		    return null;
		  } 
	}

}
