import socket
import sys
import hashlib
import os.path
import random
import threading
from os import path
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


DISCONNECT_MESSAGE = "!DISCONNECT"
close_kdc = "close_kdc"
def handle_client(conn, addr):
    connected = True
    while connected:
        req = conn.recv(1024)
        if req:
            if req == bytes(DISCONNECT_MESSAGE,"utf-8") :
                connected = False
                continue
            type = req[0:3].decode()
            if int(type) == 301 :
                req = req.decode("utf-8")
                elements = req.split(" ")
                m = hashlib.md5()
                m.update(bytes(elements[3], "utf-8"))
                hash = m.hexdigest()
                #:alice:10.4.5.11:35678:ABCDEFabcdef123456789=:
                msg = ":"+elements[4]+":"+elements[1]+":"+elements[2]+":"+hash+":\n"
                flag = 0
                if path.exists(pwdfile) :
                    with open(pwdfile, "r") as f:
                        lines = f.readlines()
                    with open(pwdfile,"w") as f:
                        for line in lines:
                            if elements[4] in line.strip("\n"):
                                flag = 1
                                f.write(msg)
                            else :
                                f.write(line)
                        if flag == 0:
                            f.write(msg)
                else :
                    with open(pwdfile,"w") as f:
                        f.write(msg)


                clientMsg = "302 "+elements[4]
                conn.send(bytes(clientMsg, "utf-8"))

            if int(type) == 305 :
                iv = req[3:19]
                size = req[19:21]
                size = int(size.decode())
                end = 21+size
                enc_msg = req[21:end]
                ida = req[end:].decode()
                with open(pwdfile, "r") as f:
                    lines = f.readlines()
                    for line in lines :
                        line = line.strip("\n")
                        if ida in line:
                            parts = line.split(":")
                            ipA = parts[2]
                            portA = parts[3]
                            KA = parts[4]
                cipher = AES.new(bytes(KA,"utf-8"), AES.MODE_CBC, iv)
                data = unpad(cipher.decrypt(enc_msg),16).decode("utf-8")
                parts = data.split(" ")
                idb = parts[1]
                nonce = parts[2]
                with open(pwdfile,"r") as f:
                    lines = f.readlines()
                    for line in lines :
                        if idb in line:
                            parts = line.split(":")
                            ipB = parts[2]
                            portB = parts[3]
                            KB = parts[4]

                characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                ks = ''
                for i in range(0, 8):
                    ks += random.choice(characters)

                msgA = ks +" "+ ida +" "+ idb +" "+ nonce +" "+ ipB +" "+ portB
                msgB = ks +" "+ ida +" "+ idb +" "+ nonce +" "+ ipA +" "+ portA

                aes = AES.new(KA.encode("utf-8"), AES.MODE_CBC, iv)
                encA = aes.encrypt(pad(bytes(msgA, "utf-8"), 16))
                aes = AES.new(KB.encode("utf-8"), AES.MODE_CBC, iv)
                encB = aes.encrypt(pad(bytes(msgB, "utf-8"), 16))

                code = "306"
                final = bytes(code,"utf-8") + bytes(str(len(encA)),"utf-8") + encA + iv + encB

                conn.send(final)

    conn.close()
    exit()

portid = int(input("Enter PortId : "))
pwdfile = input("Enter pwdfile : ")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
hostname = socket.gethostname()
s.bind((hostname, portid))
s.listen()
IPAddr = socket.gethostbyname(hostname)
print(f"HostName : {hostname}")
print(f"IP Address : {IPAddr}")
print(f"Starts TCP server to listen on port {portid}" )
print("Waiting for messages from clients !")

while True:

    conn, addr = s.accept()
    print(f"Connection from {addr} established !")
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()
