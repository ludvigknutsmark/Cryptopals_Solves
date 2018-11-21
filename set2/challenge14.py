# Main imports
import os
import base64
import sys
from random import randint

# Own code imports
from aesecb import *
from aescbc import *

random_bytes = "aousdhgiauajff"

def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    ecb_attack_hard(key)
 
def encrypt(msg, key):
    append_text = "YELLOW SUBMARINE"
 
    msg = random_bytes + msg + append_text
    return ecb_encrypt(key, msg)

def ecb_attack_hard(key):
    last_byte = ""
    cryptomap = {}

    for i in range(86,87):
        msg = "A"*128
        ciphertext = encrypt(msg, key)
        
        # A * 16 in this cipher. 
        # Find first instance of this and then we know the prefix len, remove that prefix and continue
        #ciphertext[len(ciphertext)-48:len(ciphertext)-32]
        
        a_string = ciphertext[len(ciphertext)-64:len(ciphertext)-48]
        new_cipher = ciphertext[ciphertext.find(a_string):len(ciphertext)]
        #print new_cipher
        prefix_len = ciphertext.find(a_string)
        print "prefix len", prefix_len
        #This time I know that the prefix byte count is less than 16. So now we need to find the ight offset

        # We also know that the target byte length is 16. So the prefix length
        # is (target_len-input_len)

        # (128-16) % 16
        for i in range(0,16):
            msg = "A"*(128+i)
            ciphertext = encrypt(msg, key)
            print len(ciphertext), i
        
        # We notice the changes in i = 2. Which means that the prefix length is 16-2 = 14

        # Since we now know the offset at which the prefix start. We can utilize the same attack as in challenge 12
main()
