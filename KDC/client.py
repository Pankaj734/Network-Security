import socket
import time
import sys
import hashlib
import random
from bitstring import BitStream, BitArray
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

myname = input("Enter name : ")
type = input("Type S if you are sender else R : ")
if(type == "S"):
    othername = input("Enter othername : ")
    inputfile = input("Enter input filename : ")
    clientport = "12345"
else :
    outenc = input("Enter encrypted filename : ")
    outfile = input("Enter output filename : ")
    clientport = "2345"

kdcip = input("Enter KDC's IP address : ")
kdcport = int(input("Enter KDC's port number : "))

DISCONNECT_MESSAGE = "!DISCONNECT"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
hostname = socket.gethostname()
client.connect((hostname, kdcport))
ip = socket.gethostbyname(hostname)

MasterKey = get_random_bytes(12)
MasterKey = BitArray(MasterKey)
MasterKey = MasterKey.bin
#Registration
RegRequest = "301 "+str(ip)+" "+clientport+" "+MasterKey+" "+myname


client.send(bytes(RegRequest, "utf-8"))
response = client.recv(1024)
response = response.decode("utf-8")
if "302" in response :
    print("Registration successful !")
else:
    print("Registration unsuccessful..")

client.send(bytes(DISCONNECT_MESSAGE,"utf-8"))
client.close()
print("Sleeping for 15 secs")
time.sleep(15)

if type == "S" :
    data = myname +" "+ othername +" "+ "10101"
    iv = get_random_bytes(16)
    m = hashlib.md5()
    m.update(bytes(MasterKey, "utf-8"))
    hash = m.hexdigest()
    hash = hash.encode("utf-8")
    aes = AES.new(hash, AES.MODE_CBC, iv)
    enc = aes.encrypt(pad(bytes(data, "utf-8"), 16))
    size = bytes(str(len(enc)),"utf-8")
    code = "305"
    msg = bytes(code,"utf-8")+iv+size+enc+bytes(myname,"utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = socket.gethostname()
    s.connect((hostname, kdcport))
    s.send(msg)

    connected = True
    while connected:

        response = s.recv(1024)
        if response :
            size = int(response[3:5].decode("utf-8"))
            size = 5+size
            enc_msgA = response[5:size]
            iv = response[size:size+16]
            aes = AES.new(hash, AES.MODE_CBC, iv)
            data = unpad(aes.decrypt(enc_msgA),16).decode("utf-8")
            data = data.split(" ")
            ks = data[0]
            ipb = data[4]
            portb = data[5]
            connected = False
            s.send(bytes(DISCONNECT_MESSAGE,"utf-8"))
            s.close()

            m = hashlib.md5()
            m.update(bytes(ks, "utf-8"))
            ks = m.hexdigest()
            ks = ks.encode("utf-8")
            aes = AES.new(ks, AES.MODE_CBC, iv)
            f = open(inputfile,'rb')
            data = f.read()
            f.close()
            enc = iv + aes.encrypt(pad(data, 16))
            f = open("outenc.txt",'wb')
            f.write(enc)
            f.close()
            print("Encrypted file name is outenc.txt")

            r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hostname = socket.gethostname()
            r.connect((hostname, int(portb)))
            start = size+16
            enc_msgB = response[start:]
            code = "309"
            enc_msgB = bytes(code, "utf-8")+bytes(str(len(enc_msgB)),"utf-8")+iv+enc_msgB+bytes(myname,"utf-8")

            r.send(enc_msgB)
            time.sleep(5)
            r.send(bytes(DISCONNECT_MESSAGE,"utf-8"))
            r.close()


if type == "R" :
    r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = socket.gethostname()
    r.bind((hostname, int(clientport)))
    r.listen()

    while True:
        conn, address = r.accept()
        print(f"sender Connection from {address} established !")

        connected = True
        while connected:

            msg = conn.recv(1024)
            if msg :
                if msg == bytes(DISCONNECT_MESSAGE,"utf-8"):
                    connected = False
                    continue
                size = int(msg[3:5].decode("utf-8"))
                iv = msg[5:21]
                enc_msgB = msg[21:size+21]
                m = hashlib.md5()
                m.update(bytes(MasterKey, "utf-8"))
                hash = m.hexdigest()
                hash = hash.encode("utf-8")
                aes = AES.new(hash, AES.MODE_CBC, iv)
                data = unpad(aes.decrypt(enc_msgB),16)
                data = data.decode("utf-8")
                data = data.split(" ")
                ks = data[0]
                enc_ida = data[1]
                ipA = data[4]
                portA = data[5]

                ida = msg[size+21:].decode("utf-8")
                if enc_ida != ida :
                    print("Something is weird... IDA don't match !")
                else :
                    f = open(outenc, "rb")
                    iv = f.read(16)
                    cyphertext = f.read()
                    f.close()
                    m = hashlib.md5()
                    m.update(bytes(ks, "utf-8"))
                    ks = m.hexdigest()
                    ks = ks.encode("utf-8")
                    aes = AES.new(ks, AES.MODE_CBC, iv)
                    plaintext = unpad(aes.decrypt(cyphertext),16)
                    f = open(outfile,'w')
                    f.write(plaintext.decode("utf-8"))
                    f.close()
                    r.close()
                    exit()
