package main;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter; 
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException; 
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map; 

public class GenerateKey {
	/*./lab3 CreateKeys UserNameListFile RSAKeySize
	The UserNameListFile will contain a set of users, one per line.
	RSAKeySize is either 1024 or 2048.
	For each user,randomly generate an RSA keypair and store privatekey and publickey in 
	user_priv_keylen.txt and user_pub_keylen.txt respectively; where keylen is either 1024 or 2048.*/
	
	public GenerateKey(String[] args){
		generate_keys(args);
	}

	private void generate_keys(String[] args) {
		// TODO Auto-generated method stub
		if(args.length != 3) {
			System.out.println("Error in parameters");
			System.exit(0);
		}
		String UserNameListFile = args[1];
		int rsaKeySize = Integer.parseInt(args[2]); 
		List<String> names = getNames(UserNameListFile);
		if(names == null) {
			System.out.println("Error in name file");
			System.exit(0);
		}
		Map<String, KeyPair> keys = new LinkedHashMap<String, KeyPair>(); 
		String name = null;
		for(int i = 0; i < names.size(); i++) {
			name = names.get(i);
			try {
				keys.put(name, generateKeys(rsaKeySize));
			} catch (NoSuchAlgorithmException e) { 
				e.printStackTrace();
			} 
		}
		
		try {
			writePublicKey(keys);
			writePrivateKey(keys);
		} catch (FileNotFoundException e) { 
			e.printStackTrace();
		}
		
	}
	
	private static List<String> getNames(String userNameListFile) { 
		List<String> names = new LinkedList<String>();
		 try {
		    BufferedReader reader = new BufferedReader(new FileReader(userNameListFile));
		    String line;
		    while ((line = reader.readLine()) != null) names.add(line); 
		    reader.close();
		    return names;
		  } catch (Exception e) { 
		    e.printStackTrace();
		    return null;
		  } 
	}
	
	private static KeyPair generateKeys(int rsaKeySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(rsaKeySize);
        KeyPair pair = keyGen.generateKeyPair();
        return pair; 
	}

	private static void writePublicKey(Map<String, KeyPair> keys) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter("user_pub_keylen.txt"); 
	     for (Map.Entry<String, KeyPair> entry : keys.entrySet()) {
	    	 writer.println(entry.getKey()+ " "+entry.getValue().getPublic());  
	     }
	     writer.close(); 
	}
	
	private static void writePrivateKey(Map<String, KeyPair> keys) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter("user_priv_keylen.txt"); 
	     for (Map.Entry<String, KeyPair> entry : keys.entrySet()) { 
	    	 writer.println(entry.getKey()+ " "+entry.getValue().getPrivate());  
	     }
	     writer.close();
	} 
}