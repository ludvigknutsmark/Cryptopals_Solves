#!/usr/bin/python
import sys
sys.path.insert(0,r'/home/ludvig/cryptopals')

# Own imports
from set2.aescbc import *
from set2.pkcs7 import *

def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    
    IV = bytearray(16) 
    msg = fix_input("A"*16, key)
    
    # Attacker intercept
    ciphertext = msg[:16]+"\x00"*16+msg[:16]
    
    validate = verify_ascii(ciphertext, key)
    if validate == True:
        print "Verified successfully!"
    else:
        print "ERROR: ",validate
        found_key = xor(list(validate[:16]), list(validate[32:48]))
        print "FOUND KEY: ", found_key == key

def fix_input(src, key):
    # Sanitize the user input
    src = src.replace("=", "")
    src = src.replace(";", "")
    # Prepend and append the string
    prepend_str = "comment1=cooking%20Mcs;userdata="
    append_str = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    dst = prepend_str + src + append_str
    return cbc_encrypt(key, dst, key)


def verify_ascii(src, key):
    plaintext = cbc_decrypt(key, src, key)
    #plaintext = pkcs7_validate(unpadded)
    for i in plaintext:
        if ord(i) > 127:
            return plaintext
    
    return True

main()

