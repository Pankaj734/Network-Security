import socket
import os
import sys
import hashlib
import random
import pickle
from bitstring import BitStream, BitArray
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
format = "utf-8"

situation = input("S for same & D for different machine usage : ")

if(situation == "S") :
    port = int(input("Port : "))
    user = input("Username : ")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((socket.gethostname(), port))
elif situation == "D" :
    ipaddr = bytes(input("Enter sever ip : "),format)
    port = int(input("Port : "))
    user = input("Username : ")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ipaddr, port))

key = client.recv(2048)
ServerPubKey = pickle.loads(key)
f = open("server_pub.pem","wb")
f.write(ServerPubKey)
f.close()
print("server Public Key saved")

passphrase = input("Enter 8-character(a-z,0-9) password : ")
if len(passphrase) != 8 :
    print("password needs to be 8 chars ")
    exit()
session_key = get_random_bytes(32)

msg = bytes(user,format)+bytes(passphrase,format)+session_key
server_key = RSA.import_key(ServerPubKey)
cipher_rsa = PKCS1_OAEP.new(server_key)
msg = cipher_rsa.encrypt(msg)

client.send(msg)

ack = client.recv(2048)

if ack == bytes("OK",format) :
    print("Authentication Successful !")
    session = True
    while(session):
        cmd = input("Enter command : ")
        if cmd == "listfiles" :
            client.send(bytes("LS",format))
            directories = client.recv(1024).decode(format)
            print(directories)
            

        elif cmd == "cwd" :
            client.send(bytes("PWD", format))
            print(client.recv(1024).decode(format))
        elif "chgdir" in cmd :
            path = cmd[7:]
            client.send(bytes("CD"+path,format))
            res = client.recv(1024)
            if res == bytes("OK",format):
                print("Successfull !")
            else :
                print("Error occured !")
        elif "cp" in cmd :
            client.send(bytes(cmd,format))
            res = client.recv(1024)
            print(res.decode(format))
        elif "mv" in cmd :
            client.send(bytes(cmd,format))
            res = client.recv(1024)
            print(res.decode(format))
        elif cmd == "logout":
            client.send(bytes(cmd,format))
            session = False
        else :
            print("Invalid command !")

else :
    print("NOK")
    print("If new user press Y for registration else N : ")
    signal = input()
    if signal ==  "Y" :
        client.send(bytes(signal,format))
        msg = client.recv(1024).decode(format)
        if msg == "OK" :
            print("Registration Successful ! ")
            exit()
    else :
        client.send(bytes(signal,format))
        print("Try Again !")
        exit()


                