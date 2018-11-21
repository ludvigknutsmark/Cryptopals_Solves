#!/usr/bin/python

# Own imports
from aescbc import *
from pkcs7 import *

def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    
    IV = bytearray(16)

    msg= fix_input("A"*16+"B"*16, key, IV)

    list_msg = list(msg)
    target = ";admin=true;AAAA"
    for i in range(32, 48):
        # 66 is the B char
        # (ord(msg[i]) ^ B => Plaintext[i], I wan't plaintext[i] to become target[i] so I calculate
        # to which bit I have to flip in order for the plaintext to become the target.
        flip_chr = (ord(msg[i])^66)^ord(target[i-32])
        list_msg[i] = chr(flip_chr)
    
    print "ISADMIN:", check_admin(''.join(list_msg), key, IV)

def fix_input(src, key, IV):
    # Sanitize the user input
    src = src.replace("=", "")
    src = src.replace(";", "")
    # Prepend and append the string
    prepend_str = "comment1=cooking%20Mcs;userdata="
    append_str = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    dst = prepend_str + src + append_str
    return cbc_encrypt(key, dst, IV)

def check_admin(ciphertext, key, IV):
    unpadded = cbc_decrypt(key, ciphertext, IV)
    plaintext = pkcs7_validate(unpadded)

    if ";admin=true;" in plaintext:
        return True
    else:
        return False

main()

