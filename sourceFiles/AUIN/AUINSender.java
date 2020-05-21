package AUIN;

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

public class AUINSender {
	
	public AUINSender(String[] args) {
		aUINSender(args);
	}

	public static void main(String[] args) {
		new AUINSender(args); 
	}

	private void aUINSender(String[] args) {
		// TODO Auto-generated method stub
		//./lab3 CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg
		if(args.length != 9) {
			System.out.println("Error in parameters");
			System.exit(0);
		}  
		String sender = args[2]; 
		String emailInputFile = args[4]; //input plain text fichier (in ASCII format) 
		String emailOutputFile = args[5]; //output of the encryption algorithms (in binary format)  
		String digestAlg = args[6]; //sha512 sha3-512 
		int RSAKeySize = Integer.parseInt(args[8]);//1024 or 2048
		
		String message = getMessage(emailInputFile);
		System.out.println("Message to send : "+message);
		
		String hash = generateHash(message, digestAlg);
		System.out.println("Hash of the message : "+hash);
		
		Map<String, String> privateA = getPrivateKey(sender);
		String privateKeyA = "";
		String mudulus = "";
		for (Entry<String, String> entry : privateA.entrySet()) {
			privateKeyA = entry.getKey();
			mudulus = entry.getValue(); 
	     }
		System.out.println("Private Key Receiver : "+privateKeyA+"\nModulus of receiver : "+mudulus);
		
		byte[] cipherHash = crypteHash(privateKeyA, mudulus, hash, RSAKeySize);  
		writeInFile(cipherHash, message, emailOutputFile); 
	}
	
	private static void writeInFile(byte[] cipherHash, String message, String emailOutputFile) {
		// TODO Auto-generated method stub
		try {   
			String cipherHsh = Base64.getEncoder().encodeToString(cipherHash);   
			PrintWriter writer = new PrintWriter(emailOutputFile); 
		    writer.println(cipherHsh); 
		    writer.println(message); 
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
		try {
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
		  } catch (Exception e){ 
		    e.printStackTrace();
		    return null;
		  }  
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
		  }catch (Exception e) {
		    e.printStackTrace();
		    return null;
		  } 
	}

}
