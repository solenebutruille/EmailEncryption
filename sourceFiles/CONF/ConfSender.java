package CONF;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.math.BigInteger; 
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry; 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey; 
 

public class ConfSender {
	
	public ConfSender(String[] args) {
		confSender(args);
	}

	public static void main(String[] args) {
		new ConfSender(args); 
	}

	private void confSender(String[] args) {
		// TODO Auto-generated method stub 
		//./lab3 CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg
		if(args.length != 9) {
			System.out.println("Error in parameters");
			System.exit(0);
		}  
		String receiver = args[3];
		String emailInputFile = args[4]; //input plain text fichier (in ASCII format) 
		String emailOutputFile = args[5]; //output of the encryption algorithms (in binary format)  
		String encryAlg = args[7]; //Aes Des 
		
		String message = getMessage(emailInputFile);
		System.out.println("Message to send : "+message);
		
		SecretKey Ks = generateKs(encryAlg); 
		System.out.println("Ks : "+Base64.getEncoder().encodeToString(Ks.getEncoded()));
		
		Map<byte[], byte[]> cripteReturn = crypteMessage(Ks, message, encryAlg);
		byte[] cipherTextM = null;
		byte[] iv = null;
		for (Entry<byte[], byte[]> entry : cripteReturn .entrySet()) {
			cipherTextM = entry.getKey();
			iv = entry.getValue(); 
	    } 
		System.out.println("Iv : "+Base64.getEncoder().encodeToString(iv));
		
		Map<String, String> infosRecevier = getKeyReceiver(receiver, 0);
		String keyPublicB = "";
		String mudulusB = "";
		for (Entry<String, String> entry : infosRecevier .entrySet()) {
			keyPublicB = entry.getKey();
			mudulusB = entry.getValue(); 
	    }
		System.out.println("Key receiver : "+ keyPublicB);
		System.out.println("Modulus receiver : "+ mudulusB);
		
		byte[] cipherTextKs = crypteKs(keyPublicB, mudulusB, Ks, iv); 
		
		writeInfosInFile(emailOutputFile, cipherTextM, cipherTextKs);  
	}
	
	private static void writeInfosInFile(String emailOutputFile, byte[] cipherTextM, byte[] cipherTextKs) {
		// TODO Auto-generated method stub
		try {  
			String cipherTextMssg = Base64.getEncoder().encodeToString(cipherTextM);
			String cipherTextks = Base64.getEncoder().encodeToString(cipherTextKs); 
			PrintWriter writer = new PrintWriter(emailOutputFile); 
		    writer.println(cipherTextks); 
		    writer.println(cipherTextMssg); 
		    writer.close();
		} catch(Exception e) {
			e.printStackTrace();
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
	   
	  
	   
	
	private static byte[] crypteKs(String kuB, String mudulusB, SecretKey ks, byte[] iv) {
		// TODO Auto-generated method stub 
		String encodedKey = Base64.getEncoder().encodeToString(ks.getEncoded());
		String encodedIv = Base64.getEncoder().encodeToString(iv);
		String parameters = encodedKey + "||" + encodedIv;
		BigInteger KeyB = new BigInteger(kuB);
		BigInteger mudulus = new BigInteger(mudulusB);   
		byte[] ciphertext = crypt(parameters, KeyB, mudulus);    
		return ciphertext;
	}

	private static Map<String, String> getKeyReceiver(String receiver, int RSAKeySize) {
		String keyPuB = "";
		String modulus = "";
		try  {
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
		  } catch (Exception e) { 
		    e.printStackTrace();
		    return null;
		  } 
	}

	private static Map<byte[], byte[]> crypteMessage(SecretKey ks, String message, String encryAlg) {
		// TODO Auto-generated method stub
		try {
			// Create the cipher, séparer pour DES
			Cipher cipher = null;
			if(encryAlg.equals("AES")) cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			else if(encryAlg.equals("DES")) cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			else System.out.println("Error in parameters encryAlg");
		    // Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, ks); 
		    // Our cleartext
		    byte[] cleartext = message.getBytes();  
		    // Encrypt the cleartext
		    byte[] ciphertext = cipher.doFinal(cleartext); 
		    byte[] encodedParams = cipher.getParameters().getEncoded();
		    return Map.of(ciphertext, encodedParams);
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		} 
	}

	private static SecretKey generateKs(Object encryAlg) {
		try {
			KeyGenerator keygen = null; //ici mettre AES ou DES
			if(encryAlg.equals("AES")) keygen = KeyGenerator.getInstance("AES");
			else if(encryAlg.equals("DES")) keygen = KeyGenerator.getInstance("DES");
		    SecretKey Ks = keygen.generateKey(); 
		    return Ks;
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
		  } catch (Exception e){ 
		    e.printStackTrace();
		    return null;
		  } 
	}
}