import socket
import os
import sys
import base64
import hashlib
import time
import random
import shutil
import pickle
from bitstring import BitStream, BitArray
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Protocol.KDF import PBKDF2
format = "utf-8"

pubkey = open("serverkeys\\serverpub.pem",'wb')
key = RSA.generate(1024)
public_key = key.publickey().exportKey("PEM") 
pubkey.write(public_key)
privkey = open("serverkeys\\serverpriv.pem",'wb')
private_key = key.exportKey("PEM")
privkey.write(private_key)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)
server.bind((IPAddr, 12345))
server.listen()

print("IP : "+IPAddr)
print("Port : 12345")

f = open("serverkeys\\serverpub.pem","rb")
key = f.read()
f.close()

ClientActive = True
while(ClientActive) :
    client, addr = server.accept()
    print(f"Connection established {client}")
    client.send(pickle.dumps(public_key))
    time.sleep(5)
    res = client.recv(1024)
    time.sleep(5)
    server_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(server_key)
    res = cipher_rsa.decrypt(res)
    size = len(res)
    usersize = size-(8+32)
    username = res[0:usersize].decode(format)
    passphrase = res[usersize:usersize+8].decode(format)
    session_key = res[usersize+8 : ]
    
    try :
        filename = username+".txt"
        f = open("UserCredentials\\"+filename,"rb")
        msg = bytes("OK",format)
        client.send(msg)
    except :
        msg = bytes("NOK",format)
        client.send(msg)
        time.sleep(5)
    
    #if user does not exist
    if msg.decode(format) == "NOK" :
        resp = client.recv(1024).decode(format)
        if resp == "N" :
            ClientActive = False
        elif resp == "Y" :
            zeroes = ""
            for i in range(0,120):
                zeroes += "0"
        
            key = PBKDF2(passphrase, zeroes, dkLen=32)
            iv = get_random_bytes(16)

            aes = AES.new(key, AES.MODE_CBC, iv)
            data0 = "0000000000000000"
            data0 = bytes(data0, format)

            enc_data = aes.encrypt(data0)

            final = iv + enc_data
            filename = username+".txt"
            f = open("UserCredentials\\"+filename,"wb")
            user64 = base64.b64encode(bytes(username,format))
            final64 = base64.b64encode(final)
            f.write(user64 + bytes("\n",format) + final64)
            f.close()
            client.send(bytes("OK",format))
            ClientActive = False 

    else :
        
        # if user exists
        lines = f.readlines()
        for i in range(0,2) :
            lines[i] = base64.b64decode(lines[i].strip(bytes("\n","utf-8"))) 

        zeroes = ""
        for i in range(0,120):
            zeroes += "0"
        
        key = PBKDF2(passphrase, zeroes, dkLen=32)
        
        passphrase = bytes(passphrase,format)
        linetwo = lines[1]
        iv = linetwo[0:16]

        aes = AES.new(key, AES.MODE_CBC, iv)
        data0 = "0000000000000000"
        data0 = bytes(data0, format)

        enc_data = aes.encrypt(data0)

        final = iv + enc_data
        final64 = base64.b64encode(final)

        if final64 == lines[1] :
            msg = bytes("OK",format)
            client.send(msg)
            time.sleep(5)


        session = True 
        while(session) :
            cmd = client.recv(1024).decode(format)
            time.sleep(5)

            if cmd == "LS" :
                arr = os.listdir('.')
                size = len(arr)
                string = ""
                for i in range(0,size) :
                    string += arr[i]
                    string += "\n"
                
                client.send(bytes(string,format))

            elif cmd == "PWD" :
                dir = os.getcwd()
                client.send(bytes(dir,format))
                time.sleep(5)
            
            elif "CD" in cmd :
                path = cmd[2:]
                os.chdir(path)
                client.send(bytes("OK",format))
                time.sleep(5)
            
            elif "cp" in cmd :
                parts = cmd.split(" ")
                filename = parts[1]
                src = parts[2]+filename
                dst = parts[3]+filename

                try:
                    shutil.copy(src,dst)
                    client.send(bytes("Copy DONE !","utf-8"))
                    time.sleep(5)
                except :
                    client.send(bytes("Error Occured","utf-8"))
                    time.sleep(5)
                
            elif "mv" in cmd :
                parts = cmd.split(" ")
                filename = parts[1]
                src = parts[2]+filename
                dst = parts[3]+filename

                try:
                    shutil.move(src,dst)
                    client.send(bytes("Move DONE !","utf-8"))
                except :
                    client.send(bytes("Error Occured","utf-8"))

            elif cmd == "logout" :
                session = False
                ClientActive = False
                print("*********Shuting Down !*********")
