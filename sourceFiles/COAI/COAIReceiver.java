package COAI;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class COAIReceiver {
	
	public COAIReceiver(String[] args) {
		cOAIReceiver(args);
	}

	public static void main(String[] args) {
		new COAIReceiver(args); 
	}

	private void cOAIReceiver(String[] args) {
		// TODO Auto-generated method stub
	//	./lab3 ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg
		 if(args.length != 8) {
				System.out.println("Error in parameters");
				System.exit(0);
		}    
		String sender = args[2];
		String receiver = args[3];
		String secureInputFile = args[4]; 
		String plainTextOutputFile = args[5];  
		String digestAlg = args[6]; 
		String encryAlg = args[7]; //Aes Des 
	
		Map<String, String> fileContent = getContentFile(secureInputFile); 
		String cipherTextKeys = null;
		String cipherCryptedWithKs = null;
		for (Entry<String, String> entry : fileContent .entrySet()) {
			cipherTextKeys = entry.getKey();
			cipherCryptedWithKs = entry.getValue(); 
	     } 
		
		Map<String, String> privateB = getPrivateKey(receiver);
		String privateKeyB = "";
		String mudulus = "";
		for (Entry<String, String> entry : privateB.entrySet()) {
			privateKeyB = entry.getKey();
			mudulus = entry.getValue(); 
	     }
		System.out.println("Private Key Receiver : "+privateKeyB+"\nModulus Receiver : "+mudulus);
		
		String parameterDecryption = decrypt(cipherTextKeys, privateKeyB, mudulus);  
		
		String ks = parameterDecryption.substring(0, parameterDecryption.indexOf("|"));
		String kh = parameterDecryption.substring(parameterDecryption.indexOf("|")+2, parameterDecryption.lastIndexOf("||")); 
		String iv = parameterDecryption.substring(parameterDecryption.lastIndexOf("||")+2, parameterDecryption.length()); 
		
		System.out.println("ks: " +ks);
		System.out.println("kh: " +kh);
		System.out.println("iv: " +iv);
		
		String hashAndMessage = decryptMessage(cipherCryptedWithKs, ks, iv, encryAlg);
		
		String encryptHash = hashAndMessage.substring(0, hashAndMessage.indexOf("|"));
		String message = hashAndMessage.substring(hashAndMessage.indexOf("|")+2, hashAndMessage.length());
		System.out.println("Original message : "+message);
		
		Map<String, String> infosRecevier = getKeySender(sender);
		String keyPublicA = "";
		String mudulusA = "";
		for (Entry<String, String> entry : infosRecevier .entrySet()) {
			keyPublicA = entry.getKey();
			mudulusA = entry.getValue(); 
	    }
		System.out.println("Key Sender : "+ keyPublicA);
		System.out.println("Modulus Sender : "+ mudulusA); 
		
		String hash = decrypt(encryptHash, keyPublicA, mudulusA); 
		System.out.println("Hash Received : "+ hash); 
		  
		String hashFromMessageReceived = generateHash(message, kh, digestAlg);
		System.out.println("Hash genereated : "+hashFromMessageReceived);
		
		if(compareHash(hash, hashFromMessageReceived)) {
			writeMessageInFile(message, plainTextOutputFile);
			System.out.println("Texte was not corrupted");
		} else {
			System.out.println("Texte was corrupted");
		}

	}

	
	private static void writeMessageInFile(String message, String plainTextOutputFile) {
		// TODO Auto-generated method stub
		try {   
			PrintWriter writer = new PrintWriter(plainTextOutputFile); 
		    writer.println(message);  
		    writer.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private static boolean compareHash(String hash, String hashMessage) {
		// TODO Auto-generated method stub
		if(hash.length() == hashMessage.length()) return hash.equals(hashMessage);
		else hashMessage = (new StringBuilder(hashMessage)).deleteCharAt(hashMessage.length()-1).toString();
		return hash.equals(hashMessage);
	}

	private static String generateHash(String message, String kh, String digestAlg) {
		// TODO Auto-generated method stub 
	    try { 
	    	String plaintext = kh + "||" + message;
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


	private static Map<String, String> getKeySender(String receiver) {
		String keyPuA = "";
		String modulus = "";
		 try
		  {
		    BufferedReader reader = new BufferedReader(new FileReader("user_pub_keylen.txt")); 
		    String line = "";
		    while ((line = reader.readLine()) != null) {
		    	if(line.contains(receiver)) {
		    		line = reader.readLine();
		    		line = reader.readLine();
		    		modulus = (String) line.subSequence(11, line.length());
		    		line = reader.readLine();
		    		keyPuA = (String) line.subSequence(19, line.length()); 
		    	} 
		    }
		    reader.close();
		    return Map.of(keyPuA, modulus);
		  }
		  catch (Exception e)
		  {
		    System.err.format("Exception occurred trying to read '%s'.", "user_pub_keylen.txt");
		    e.printStackTrace();
		    return null;
		  } 
	}


	private static String decryptMessage(String cipherCryptedWithKs, String ks, String iv, String encryptAlg) {
		byte[] decodedKey = Base64.getDecoder().decode(ks);
		byte[] decodedIv = Base64.getDecoder().decode(iv);
		byte[] decodedCipher = Base64.getDecoder().decode(cipherCryptedWithKs);
		String algo = "";
		if(encryptAlg.equals("aes-256-cbc")) algo = "AES";
		else if(encryptAlg.equals("des-ede3-cbc")) algo = "DES";
		else System.out.println("Error in parameters encryAlg");
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, algo);
		
		AlgorithmParameters params = null;
		try {
			if(encryptAlg.equals("aes-256-cbc")) params = AlgorithmParameters.getInstance("AES");
			else if(encryptAlg.equals("des-ede3-cbc")) params = AlgorithmParameters.getInstance("DES");
			else System.out.println("Error in parameters encryAlg"); 
			
			params.init(decodedIv);
	        Cipher cipher = null;
	        if(encryptAlg.equals("aes-256-cbc")) cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			else if(encryptAlg.equals("des-ede3-cbc")) cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			else System.out.println("Error in parameters encryAlg"); 
	        cipher.init(Cipher.DECRYPT_MODE, originalKey, params);
	        byte[] recovered = cipher.doFinal(decodedCipher); 
	
	        return new String(recovered, StandardCharsets.UTF_8); 
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}


	private static byte[] removeOneByte(byte[] input) {
	    byte[] result = new byte[input.length-1];
	    for (int i = 0; i < result.length; i++) {
	      result[i] = input[i+1];
	    }
	    return result;
	  }
	
	private static BigInteger decrypt(BigInteger ciphertext, BigInteger exponent, BigInteger modulus) {
	    return ciphertext.modPow(exponent, modulus);
	  }
	
	 public static byte[] decryptInBytes(byte[] ciphertext, BigInteger exponent, BigInteger modulus) {
		    return removeOneByte(decrypt(new BigInteger(ciphertext), exponent, modulus).toByteArray());
	  }    
	  
	  
	  public static String decryptInString(byte[] ciphertext, BigInteger exponent, BigInteger modulus) {
	    return new String(decryptInBytes(ciphertext, exponent, modulus));
	  }
	  
	private static String decrypt(String encryptHash, String publicKeyA, String mudulus) {
		// TODO Auto-generated method stub 
		BigInteger exponent = new BigInteger(publicKeyA);
		BigInteger modulus = new BigInteger(mudulus);   
		byte[] decodedKeys = Base64.getDecoder().decode(encryptHash);  
		String plaintext = decryptInString(decodedKeys, exponent, modulus);   
		return plaintext;
	}

	private static Map<String, String> getPrivateKey(String receiver) {
		// TODO Auto-generated method stub
		String keyPrB = "";
		String modulus = "";
		 try
		  {
		    BufferedReader reader = new BufferedReader(new FileReader("user_priv_keylen.txt")); 
		    String line = "";
		    while ((line = reader.readLine()) != null) {
		    	if(line.contains(receiver)) {
		    		line = reader.readLine();
		    		line = reader.readLine();
		    		modulus = (String) line.subSequence(11, line.length());
		    		line = reader.readLine();
		    		keyPrB = (String) line.subSequence(20, line.length()); 
		    	} 
		    }
		    reader.close();
		    return Map.of(keyPrB, modulus);
		  }
		  catch (Exception e)
		  {
		    System.err.format("Exception occurred trying to read '%s'.", "user_pub_keylen.txt");
		    e.printStackTrace();
		    return null;
		  }
	}

	private static Map<String, String> getContentFile(String secureInputFile) {
		// TODO Auto-generated method stub
		String cipherTextKeys = null;
		String cipherCryptedWithKs = null; 
		 try {
		    BufferedReader reader = new BufferedReader(new FileReader(secureInputFile));  
		    cipherTextKeys = reader.readLine(); 
		    cipherCryptedWithKs = reader.readLine(); 
		    reader.close();   
		    return Map.of(cipherTextKeys, cipherCryptedWithKs);
		  }  catch (Exception e) {
		    System.err.format("Exception occurred trying to read '%s'.", secureInputFile);
		    e.printStackTrace();
		    return null;
		  }    
	}

}
