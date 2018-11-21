# Main imports
import os
import base64
import sys
from random import randint

# Own code imports
from pkcs7 import *
from aesecb import *
from aescbc import *


def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    attack = ecb_attack(key)

def encryption_oracle(msg):
    key = os.urandom(16)
    
    pre_data_size = randint(5,10)
    pre_data = os.urandom(pre_data_size)
    
    post_data_size = randint(5,10)
    post_data = os.urandom(post_data_size)
    msg = pre_data + msg + post_data

    mode = randint(0,1)
    
    if(mode == 0):
        return ecb_encrypt(key, msg)
    else:
        iv = os.urandom(16)
        return cbc_encrypt(key, msg, iv)
    
def detection_oracle():
    msg = "YELLOW SUBMARINE"
    for i in range(4):
        msg += msg
    
    ciphertext = encryption_oracle(msg)
    if(ciphertext[16:32] == ciphertext[32:48]):
        print "ECB"
    else:
        print "CBC"

def ecb_attack(key):
    append_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
   
    input_str = "A"*32
    msg = input_str + base64.b64decode(append_text)
    ciphertext = ecb_encrypt(key, msg)
    print ciphertext, " ", len(ciphertext)

    # .3
    if ciphertext[:16] == ciphertext[16:32]:
        print "ECB MODE DETECTED"
    # .4 
    print
    last_byte = ""
    cryptomap = {}
    letters = ["R"]
    for k in range(1, len(base64.b64decode(append_text))-1):
	for i in range(0, 254):
	    last_byte = chr(i)
	    msg = "A"*(143-k)
            for j in range(len(letters)):
                msg+=letters[j]
            msg += last_byte + base64.b64decode(append_text)
            ciphertext = ecb_encrypt(key, msg)
	    cryptomap[ciphertext[128:144]] = last_byte
    
        correct_message = "A"*(143-k)
        correct_message += base64.b64decode(append_text)
        ciphertext = ecb_encrypt(key, correct_message)
        letter = cryptomap[ciphertext[128:144]]
        letters.append(letter)
    
    print ''.join(letters)
    print 
    print "-------ANSWER------"
    print
    print base64.b64decode(append_text)

main()
