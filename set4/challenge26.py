#!/usr/bin/python
import sys,struct
sys.path.insert(0, r'/home/ludvig/cryptopals')
from random import randint
# Own imports
from set3.aes_ctr import *
from set2.aescbc import xor

def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    
    nonce = struct.pack('<Q', randint(0, 256)) 
    msg= fix_input("A"*16, key, nonce)
    print "Before flipping->ISADMIN:", check_admin(msg, key, nonce)
    # Find the keystream and flip each byte so flipped[i]^keystream[i] = target[i]
    keystream = xor(list(msg[32:48]), list("A"*16))
    target = ";admin=true;"
    list_msg = list(msg)
    for i in range(32, len(target)+32):
        list_msg[i] = chr(ord(keystream[i-32])^ord(target[i-32]))
    
    print "After flipping->ISADMIN:", check_admin(''.join(list_msg), key, nonce)

def fix_input(src, key, nonce):
    # Sanitize the user input
    src = src.replace("=", "")
    src = src.replace(";", "")
    # Prepend and append the string
    prepend_str = "comment1=cooking%20Mcs;userdata="
    append_str = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    dst = prepend_str + src + append_str
    return aes_ctr(key, nonce, dst)

def check_admin(ciphertext, key, nonce):
    plaintext = aes_ctr(key, nonce, ciphertext)
    if ";admin=true;" in plaintext:
        return True
    else:
        return False

main()

