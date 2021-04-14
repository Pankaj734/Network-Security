Libraries that need to installed beforehand :
  bitstring - pip install bitstring
  Cryptodome - pip install pycryptodomex (for windows)

The code will work only for Python3.

Executing KDC (in terminal-1):
  python3 kdc.py
  And then enter what is asked along the way.

Now in another terminal (terminal-2) execute client in receiver mode.
**NOTE** - You need to execute in receiver mode first and then in sender mode. Otherwise it won't work.

Executing Receiver (terminal-2) :
  python3 client.py
  And then enter what is asked along the way.
  **NOTE** - For the name of encrypted file, you need to write outenc.txt

The name of the message file that needs to be encrypted is :- sample.txt

Executing Sender (terminal-3) :
  python3 client.py
  And then enter what is asked along the way.

(For Windows) let say the decrypted file name is Decfile.txt . Now to check if the input file and decrypted are same use the following :
  fc.exe sample.txt Decfile.txt


I was not able to generate the script for KDC as it kept running in a while loop and I was not able to end it. So I have attached a screenshot.