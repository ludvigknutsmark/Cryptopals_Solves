from Crypto.Cipher import AES
import os
from pkcs7 import *
import binascii
import struct

def ecb_encrypt(key, msg):
    msg = pkcs7(msg)
    cipher = AES.new(key)
    ciphertext = "" 
    for i in range(0, len(msg)/16):
        ciphertext += cipher.encrypt(msg[i*16:(i+1)*16])
    return ciphertext

def ecb_decrypt(key, msg):
    cipher = AES.new(key)
    plaintext = ""
    for i in range(0, len(msg)/16):
        plaintext += cipher.decrypt(msg[i*16:(i+1)*16])
    return plaintext
