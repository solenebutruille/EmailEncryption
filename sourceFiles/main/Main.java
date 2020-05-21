package main;

import AUIN.AUINReceiver;
import AUIN.AUINSender;
import COAI.COAIReceiver;
import COAI.COAISender;
import CONF.ConfSender;
import CONF.ReceiverConf;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub 
		// ./lab3 CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg
		// ./lab3 CreateKeys UserNameListFile RSAKeySize
		// ./lab3 ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg
		try {
			String instruction = args[0];
			if(instruction.equals("CreateKeys")) { 
				new GenerateKey(args);
			} else {
				String secType = args[1];
				if(instruction.contentEquals("CreateMail") && secType.equals("CONF")) new ConfSender(args);
				if(instruction.contentEquals("CreateMail") && secType.equals("AUIN")) new AUINSender(args);
				if(instruction.contentEquals("CreateMail") && secType.equals("COAI")) new COAISender(args);
				if(instruction.contentEquals("ReadMail") && secType.equals("CONF")) new ReceiverConf(args);
				if(instruction.contentEquals("ReadMail") && secType.equals("AUIN")) new AUINReceiver(args);
				if(instruction.contentEquals("ReadMail") && secType.equals("COAI")) new COAIReceiver(args);
			}
		}catch(Exception e) {  
			System.out.println("Error in parameters.");
		}
		 
	}

}
