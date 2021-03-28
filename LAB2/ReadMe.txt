The code is written in python. I was not able to create the makefile for the python script. So, you need to compile the program manually. The program was executed and tested on a windows machine. script file also regarding the windows platform.

step-1: compile the program using the following command
	python lab2.py

step-2: Now you need to enter some inputs one after the other.
	=>if you want to create keys, enter CreateKeys UserNameListFile RSAKeySize in this order only
		CreateKeys (press enter)
		UserNames.txt (press enter)
		RSAKeysize (press enter)

	=> if you want to create/encrypt mails,
		CreateMail (press enter) 
		SecType (press enter) 
		Sender (press enter)
		Receiver (press enter)
		Mail-Sample.txt (press enter)
		EmailOutputFile  (press enter)
		DigestAlg (press enter)
		EncryAlg (press enter)
		RSAKeySize (press enter)

	=> if you want to readmail/decrypt
		ReadMail (press enter)
		SecType (press enter) 
		Sender (press enter)
		Receiver (press enter)
		SecureInputFile (press enter)
		PlainTextOutputFile (press enter)
		DigestAlg (press enter)
		EncryAlg (press enter)
		RSAKeySize (press enter)

If you want to check the difference between emailoutputfile and decryptes file on WINDOWS, you can use the following command :-
	for command line :- fc file1.extension file2.extension
	for windows powershell:- fc.exe file1.extension file2.extension

		
In case of AUIN at receiver end, no output text file is generated. After all the decryption and the hash digest extracted from the file and the new computed hash value of the extracted message is compared. The resulting output is then printed at the command line itself.
