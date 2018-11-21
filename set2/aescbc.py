from Crypto.Cipher import AES
import os
from pkcs7 import *

def cbc_encrypt(key, msg, iv):
    msg = pkcs7(msg)
    cipher = AES.new(key)
    ciphertext = ""
    for i in range(0, len(msg)/16):
        msg_iv = xor(iv, msg[i*16:(i+1)*16])
        ciphertext += cipher.encrypt(msg_iv)
        iv = ciphertext[i*16:(i+1)*16]
    return ciphertext

def cbc_decrypt(key, msg, iv):
    cipher = AES.new(key)
    plaintext = ""
    for i in range(0, len(msg)/16):
        tmp = xor(iv, cipher.decrypt(msg[i*16:(i+1)*16]))
        plaintext += tmp
        iv = msg[i*16:(i+1)*16]
        
    return plaintext

def xor(arr1, arr2):
    dst = []
    for i in range(len(arr1)):
        dst.append(chr(ord(str(arr1[i])) ^ ord(str(arr2[i]))))
    return ''.join(dst)
