package CONF;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ReceiverConf {
	
	public ReceiverConf(String[] args) {
		receiverConf(args);
	}

	public static void main(String[] args) {
		new ReceiverConf(args); 
	}
	
	private void receiverConf(String[] args) {
		// TODO Auto-generated method stub 
	//	 ./lab3 ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg
		 if(args.length != 8) {
				System.out.println("Error in parameters");
				System.exit(0);
		}    
		String receiver = args[3];
		String secureInputFile = args[4]; 
		String plainTextOutputFile = args[5];  
		String encryAlg = args[7]; //Aes Des 
		
		Map<byte[], byte[]> fileContent = getContentFile(secureInputFile); 
		byte[] crypteParameterCrypting = null;
		byte[] crypteMessage = null;
		for (Entry<byte[], byte[]> entry : fileContent .entrySet()) {
			crypteParameterCrypting = entry.getKey();
			crypteMessage = entry.getValue(); 
	     } 
		
		Map<String, String> privateB = getPrivateKeyB(receiver);
		String privateKeyB = "";
		String mudulus = "";
		for (Entry<String, String> entry : privateB .entrySet()) {
			privateKeyB = entry.getKey();
			mudulus = entry.getValue(); 
	     }
		System.out.println("privateKeyB : "+privateKeyB+"\nmudulus : "+mudulus);
		
		Map<String, String> parameterDecryption = decryptKs(crypteParameterCrypting, privateKeyB, mudulus);
		String ks = "";
		String iv = "";
		for (Entry<String, String> entry : parameterDecryption .entrySet()) {
			ks = entry.getKey();
			iv = entry.getValue(); 
	     }
		System.out.println("ks : "+ks+"\niv : "+iv);
		
		String message = decryptMessage(crypteMessage, ks, iv, encryAlg);
		System.out.println("Original message : "+message);
		
		writeMessageInFile(message, plainTextOutputFile);
		 
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

	private static String decryptMessage(byte[] crypteMessage, String ks, String iv, String encryptAlg) {
		// TODO Auto-generated method stub
		byte[] decodedKey = Base64.getDecoder().decode(ks);
		byte[] decodedIv = Base64.getDecoder().decode(iv);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, encryptAlg);
		
		AlgorithmParameters params = null;
		try {
			if(encryptAlg.equals("AES")) params = AlgorithmParameters.getInstance("AES");
			else if(encryptAlg.equals("DES")) params = AlgorithmParameters.getInstance("DES");
			else System.out.println("Error in parameters encryAlg"); 
			
			params.init(decodedIv);
	        Cipher cipher = null;
	        if(encryptAlg.equals("AES")) cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			else if(encryptAlg.equals("DES")) cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			else System.out.println("Error in parameters encryAlg"); 
	        cipher.init(Cipher.DECRYPT_MODE, originalKey, params);
	        byte[] recovered = cipher.doFinal(crypteMessage); 
	
	        return new String(recovered, StandardCharsets.UTF_8); 
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}

	private static Map<String, String> getPrivateKeyB(String receiver) {
		// TODO Auto-generated method stub
		String keyPrB = "";
		String modulus = "";
		try{
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
		  } catch (Exception e) { 
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

	private static Map<String, String> decryptKs(byte[] crypteParameterCrypting, String privateKeyB, String mudulus) {
		// TODO Auto-generated method stub
		BigInteger exponent = new BigInteger(privateKeyB);
		BigInteger modulus = new BigInteger(mudulus);  
		String plaintext2 = decryptInString(crypteParameterCrypting, exponent, modulus);  
		String ks = plaintext2.substring(0, plaintext2.indexOf("|"));
		String iv = plaintext2.substring(plaintext2.lastIndexOf("|")+1, plaintext2.length()); 
		return Map.of(ks, iv);
	}

	private static Map<byte[], byte[]> getContentFile(String secureInputFile) {
		// TODO Auto-generated method stub 
		try {
		    BufferedReader reader = new BufferedReader(new FileReader(secureInputFile));  
		    String crypteParameterCrypting = reader.readLine();
		    String crypteMessage = reader.readLine();   
		    reader.close(); 
		    return Map.of(Base64.getDecoder().decode(crypteParameterCrypting), Base64.getDecoder().decode(crypteMessage));
		 } catch (Exception e){ 
		    e.printStackTrace();
		    return null;
		  }  
	}

}
