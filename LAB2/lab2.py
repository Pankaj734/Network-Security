import sys
import hashlib
from Cryptodome.PublicKey import RSA
import random
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP, DES3
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA512, SHA3_512
from Cryptodome.Cipher import PKCS1_v1_5

def CONF_AES(s, r, i, o, sz):
    session_key = get_random_bytes(32) #32 bytes = 256 bits AES-256
    iv = get_random_bytes(16)

    recipient_key = RSA.import_key(open(r+" pub "+str(sz)+".pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    aes = AES.new(session_key, AES.MODE_CBC, iv)
    f = open(i,'rb')
    data = f.read()
    f.close()

    msg = enc_session_key + iv + aes.encrypt(pad(data,16))
    f = open(o,'wb')
    f.write(msg)
    f.close()

def CONF_DES(s,r,i,o,sz):
    while True:
        try:
            session_key = DES3.adjust_key_parity(get_random_bytes(24))
            break
        except ValueError:
            pass
    iv = get_random_bytes(8)

    recipient_key = RSA.import_key(open(r+" pub "+str(sz)+".pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher = DES3.new(session_key, DES3.MODE_CBC,iv)
    f=open(i,'rb')
    data = f.read()
    f.close()
    msg = enc_session_key + iv + cipher.encrypt(pad(data,8))
    f = open(o,'wb')
    f.write(msg)
    f.close()

def CONF_AES_dec(r,i,o,k):
    private_key = RSA.import_key(open(r+" priv "+ str(k) +".pem").read())
    f = open(i,"rb")
    esk = f.read(private_key.size_in_bytes())
    iv = f.read(16)
    ciphertext = f.read()
    f.close()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(esk)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext),16)
    f=open(o,'w')
    f.write(data.decode('utf-8'))
    f.close()

def CONF_DES3_dec(r,i,o,k):
    private_key = RSA.import_key(open(r+" priv "+ str(k) +".pem").read())
    f = open(i,"rb")
    esk = f.read(private_key.size_in_bytes())
    iv = f.read(8)
    ciphertext = f.read()
    f.close()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(esk)
    cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext),8)
    f=open(o,'w')
    f.write(data.decode('utf-8'))
    f.close()

def MessageDigest(i, dalg):
    f = open(i,'r')
    data = f.read()
    f.close()

    if dalg == 'sha512':
        h = SHA512.new(truncate='256')
        h.update(data.encode("utf-8"))
        return  h.digest()
    else :
        h = SHA3_512.new()
        h.update(data.encode("utf-8"))
        return  h.digest()

def encrypt_public_key(a_message, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_msg = encryptor.encrypt(a_message)

    return encrypted_msg

def decrypt_private_key(encrypted_msg, private_key):
    encryptor = PKCS1_OAEP.new(private_key)

    decrypted_msg = encryptor.decrypt(encrypted_msg)
    return decrypted_msg

def COAI_AES_dec(r,i,o,k):
    private_key = RSA.import_key(open(r+" priv "+ str(k) +".pem").read())
    f = open(i,"rb")
    esk = f.read(private_key.size_in_bytes())
    iv = f.read(16)
    ciphertext = f.read()
    f.close()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(esk)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext),16)
    f = open('temp.txt','wb')
    f.write(data)
    f.close()
    f = open('temp.txt','rb')
    enc_md = f.read(128)
    msg = f.read()
    f.close()
    f = open(o,'w')
    f.write(msg.decode("utf-8"))
    f.close()

def COAI_DES3_dec(r,i,o,k):
    private_key = RSA.import_key(open(r+" priv "+ str(k) +".pem").read())
    f = open(i,"rb")
    esk = f.read(private_key.size_in_bytes())
    iv = f.read(8)
    ciphertext = f.read()
    f.close()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(esk)
    cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext),8)
    f = open('temp.txt','wb')
    f.write(data)
    f.close()
    f = open('temp.txt','rb')
    enc_md = f.read(128)
    msg = f.read()
    f.close()
    f = open(o,'w')
    f.write(msg.decode("utf-8"))
    f.close()

method = input()
if method == 'CreateKeys':
    filename = input()
    keysize = int(input())
    f = open(filename,'r')
    for line in f:
        line = line.strip('\n')
        keyfile = open(line+ ' pub '+str(keysize)+'.pem','wb')
        key = RSA.generate(keysize)
        keyfile.write(key.publickey().exportKey("PEM"))
        keyfile.close()
        keyfile = open(line+ ' priv '+str(keysize)+'.pem','wb')
        keyfile.write(key.exportKey("PEM"))
        keyfile.close()
    print("Key Pairs Created!")


if method == 'CreateMail':
    type = input()
    sender = input()
    receiver = input()
    inputfile = input()
    outputfile = input()
    digest = input()
    encrypt = input()
    RSAkeysize = int(input())

    if type == 'CONF':
        if encrypt == 'aes-256-cbc':
            CONF_AES(sender, receiver, inputfile, outputfile, RSAkeysize)
        else :
            CONF_DES(sender, receiver, inputfile, outputfile, RSAkeysize)
        print("CONF encryption Finished!\n")

    if type == 'AUIN':
        md = MessageDigest(inputfile, digest)
        public_key = RSA.import_key(open(sender+" pub "+ str(RSAkeysize)+".pem").read())

        enc_md = encrypt_public_key(md, public_key)
        f = open(inputfile,'r')
        data = f.read()
        f.close()
        msg = enc_md + data.encode("utf-8")
        f=open(outputfile,'wb')
        f.write(msg)
        f.close()
        print("AUIN encryption Finished!\n")

    if type == 'COAI':
        md = MessageDigest(inputfile, digest)
        public_key = RSA.import_key(open(sender+" pub "+ str(RSAkeysize)+".pem").read())
        enc_md = encrypt_public_key(md, public_key)
        f = open(inputfile,'r')
        data = f.read()
        f.close()
        msg = enc_md + data.encode("utf-8")
        f = open('temp.txt','wb')
        f.write(msg)
        f.close()
        if encrypt == 'aes-256-cbc':
            CONF_AES(sender, receiver, 'temp.txt', outputfile, RSAkeysize)
        else :
            CONF_DES(sender, receiver, 'temp.txt', outputfile, RSAkeysize)
        print("COAI encryption Finished!\n")

if method == "ReadMail":
    type = input()
    sender = input()
    receiver = input()
    inputfile = input()
    outputfile = input()
    digest = input()
    encrypt = input()
    RSAkeysize = int(input())

    if type == "CONF":
        if encrypt == 'aes-256-cbc':
            CONF_AES_dec(receiver, inputfile, outputfile, RSAkeysize)
        else :
            CONF_DES3_dec(receiver, inputfile, outputfile, RSAkeysize)
        print("CONF decryption Finished!\n")

    if type == "AUIN":
        f=open(inputfile,'rb')
        enc_md = f.read(128)
        msg = f.read()
        f.close()
        private_key = RSA.import_key(open(sender+" priv "+ str(RSAkeysize)+".pem").read())
        dec_md = decrypt_private_key(enc_md, private_key)
        f = open('temp.txt','wb')
        f.write(msg)
        f.close()
        md = MessageDigest('temp.txt', digest)
        if dec_md == md :
            print("SUCCESS! hash values matched\n")
        else:
            print("NO SUCCESS! hash values did not matched\n")

    if  type == "COAI":
        if encrypt == 'aes-256-cbc':
            data = COAI_AES_dec(receiver, inputfile, outputfile, RSAkeysize)
        else :
            data = COAI_DES3_dec(receiver, inputfile,outputfile, RSAkeysize)
        print("COAI decryption Finished!\n")
