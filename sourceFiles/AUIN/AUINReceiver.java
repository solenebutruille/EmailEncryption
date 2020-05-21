package AUIN;

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

public class AUINReceiver {
	
	public AUINReceiver(String[] args) {
		aUINReceiver(args);
	}

	public static void main(String[] args) {
		new AUINReceiver(args); 
	}
	
	private void aUINReceiver(String[] args) {
		// TODO Auto-generated method stub
//		 ./lab3 ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg
			 if(args.length != 8) {
					System.out.println("Error in parameters");
					System.exit(0);
			}    
			String sender = args[2]; 
			String secureInputFile = args[4];  
			String digestAlg = args[6];  
		
			Map<String, String> fileContent = getContentFile(secureInputFile); 
			String crypteHash = null;
			String message = null;
			for (Entry<String, String> entry : fileContent .entrySet()) {
				crypteHash = entry.getKey();
				message = entry.getValue(); 
		     } 
			System.out.println("Message received " +message); 
			
			Map<String, String> infosSender = getKeySender(sender);
			String keyPublicA = "";
			String mudulusA = "";
			for (Entry<String, String> entry : infosSender .entrySet()) {
				keyPublicA = entry.getKey();
				mudulusA = entry.getValue(); 
		    }
			System.out.println("KeyA : "+ keyPublicA);
			System.out.println("ModulusA : "+ mudulusA);
			
			String hash = decryptHash(crypteHash, keyPublicA, mudulusA);
			System.out.println("Hash from file : "+ hash);
			
			String hashMessage = generateHash(message, digestAlg);
			System.out.println("Hash from plain message : "+ hashMessage);
			 
			if(compareHash(hash,hashMessage)) System.out.println("File was not corrupted");
			else System.out.println("File was corrupted");

	}
	
	private static boolean compareHash(String hash, String hashMessage) {
		// TODO Auto-generated method stub
		if(hash.length() == hashMessage.length()) return hash.equals(hashMessage);
		else hashMessage = (new StringBuilder(hashMessage)).deleteCharAt(hashMessage.length()-1).toString();
		return hash.equals(hashMessage);
	}

	private static String generateHash(String message, String digestAlg) {
		// TODO Auto-generated method stub  
	    try {
	        MessageDigest md = null;
	        if(digestAlg.equals("sha512")) md = MessageDigest.getInstance("SHA-512"); 
	        else if(digestAlg.equals("sha3-512")) md = MessageDigest.getInstance("SHA3-512"); 
	        else System.out.println("Error in the digest Algorithm");
	         
	        byte[] bytes = md.digest(message.getBytes(StandardCharsets.UTF_8));
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


	private static String decryptHash(String hash, String keyPublicA, String mudulusA) {
		// TODO Auto-generated method stub 
		BigInteger exponent = new BigInteger(keyPublicA);
		BigInteger modulus = new BigInteger(mudulusA);   
		byte[] hashDecrypt = Base64.getDecoder().decode(hash); 
		String plaintextHash = decryptInString(hashDecrypt, exponent, modulus);   
		return plaintextHash; 
	}

	private static Map<String, String> getKeySender(String sender) {
		// TODO Auto-generated method stub
		String keyPuA = "";
		String modulus = "";
		 try {
		    BufferedReader reader = new BufferedReader(new FileReader("user_pub_keylen.txt")); 
		    String line = "";
		    while ((line = reader.readLine()) != null) {
		    	if(line.contains(sender)) {
		    		line = reader.readLine();
		    		line = reader.readLine();
		    		modulus = (String) line.subSequence(11, line.length());
		    		line = reader.readLine();
		    		keyPuA = (String) line.subSequence(19, line.length()); 
		    	} 
		    }
		    reader.close();
		    return Map.of(keyPuA, modulus);
		  } catch (Exception e){ 
		    e.printStackTrace();
		    return null;
		  }  
	}

	private static Map<String, String> getContentFile(String secureInputFile) {
		// TODO Auto-generated method stub 
		try {
		    BufferedReader reader = new BufferedReader(new FileReader(secureInputFile));  
		    String crypteHash = reader.readLine();
		    String line = reader.readLine();
		    String message = line;
		    while ((line = reader.readLine()) != null) {
		    		message += "\n" + line;   
		    }
		    reader.close();   
		    return Map.of(crypteHash, message);
		  } catch (Exception e){
		    System.err.format("Exception occurred trying to read '%s'.", secureInputFile);
		    e.printStackTrace();
		    return null;
		  }   
	}

}
