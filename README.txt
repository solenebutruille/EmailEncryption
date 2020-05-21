My program can be launch from the Main class, but every class can also be run in local without the main.
Example about how to launch classes : 
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\AUIN\AUINReceiver.java ReadMail AUIN Louis Alix Output.txt file sha3-512 AES
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\AUIN\AUINSender.java CreateMail AUIN Louis Alix Message.txt Output.txt sha3-512 AES 1024
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\COAI\COAIReceiver.java ReadMail COAI Louis Alix Output.txt fileFinal.txt sha512 aes-256-cbc
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\COAI\COAISender.java CreateMail COAI Louis Alix Message.txt Output.txt sha512 aes-256-cbc 1024
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\CONF\ConfSender.java CreateMail CONF Louis Alix Message.txt Output.txt alg AES 1024
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\CONF\ReceiverConf.java ReadMail CONF Louis Alix Output.txt Plaintext.txt sha512 AES
java C:\Users\solen\Documents\IITM\Network Security\Lab 3\SourceFiles\main\GenerateKey.java CreateKeys Names.txt 2048
 
In order to run a program, the parameters needs to be exactly the same as the one in the assignement subject.
(java -jar lab3.jar CreateKeys UserNameListFile RSAKeySize
The UserNameListFile will contain a set of users, one per line.
RSAKeySize is either 1024 or 2048.

java -jar lab3.jar CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg RSAKeySize
SecType: CONF, AUIN, COAI
Sender/Receiver are sender and recipient of this message. 
EmailInputFile contains the input plain-text ﬁle (in ASCII format) 
EmailOutputFile contains the output of the encryption algorithms (in binary format) 
DigestAlg is one of: sha512, sha3-512 
EncryAlg is one of: des-ede3-cbc, aes-256-cbc

java -jar lab3.jar ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg)
Similar to above)


From all the tests that I did, there are no errors. 
I think I have 2 weaknesses : 
- The first one is that with RSA Key Size 1024, the hash that needs to be encoded is one character too big.
In order to fix this problem, I decided not to take into account the last character if size is 1024.
It will lose a bit of security, but knowing that a hash totally change if there is one little difference
between 2 texts, I don't think it is really important.
- My other weakness is that the code is replicated a lot of times between all the classes. Meaning that
every class is independant but I could have save some space if I had created other classes (for example
to generate hash, crypt, decrypt ...)