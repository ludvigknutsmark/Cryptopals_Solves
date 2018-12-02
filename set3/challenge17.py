#!/usr/bin/python
import sys, os, base64
sys.path.insert(0, r'/home/ludvig/cryptopals')

from random import randint

# Own imports
from set2.pkcs7 import *
from set2.aescbc import *


rand_strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ]

def main():
    pick = randint(0, len(rand_strings)-1)
    string = rand_strings[pick]
    cipher, IV = encrypt(string)
    
    plaintext = []
    
    # 1  string[16:48]
    # 2  string[0:32]
    # Maybe change this? It doesn't have to be backwards right?

    for c in xrange(len(cipher)/16, 1, -1):
        # Chose the block to decrypt from the whole ciphertext
        block = list(cipher)[(c-2)*16:c*16]
   
        c1_prime = list(block)
        P2_prime = 0
        P2 = []
        I2 = []

        # Iterate over each byte in the block
        for i in range(16):
            for j in range(255):
                # Pick C1' as the corresponding byte array to guess the right padding
                c1_prime[15-i] = chr(j)
                
                # FIRST ROUND
                # If C1' has valid padding then we know we found the right byte
                # and we know that the corresponding plaintext byte is 
                # P2[16] = C1[16] ^ (C1'[16]^ 1) <- starts with one
                # D(C2) = C1'[16] XOR 1 where D(C2) is the Intermediate state before the XOR's
                
                # This way we can find each byte which gives valid padding and like that figure out
                # the whole plaintext by doing this for each byte.

                # For the next round we put C1'[16] = 02 and C1'[15] = 00 (first round C1'[16] = 00)
                # Third round C1'[16] = 03, C1'[15] = 03 C1'[14] = 00
                if validate_token(''.join(c1_prime), IV):
                    P2_prime = i+1
                    I2.append(j^P2_prime)
                    P2.append(chr(ord(block[15-i])^I2[i]))
                    for k in range(i+1):
                        c1_prime[15-k] = chr((P2_prime+1) ^ I2[k])
                    break
            
        plaintext.insert(0, ''.join(P2[::-1]))

    try:
        print base64.b64decode(''.join(plaintext))
    except:
        print "Base64 error"



def encrypt(msg):
    f = open("key.key", "r")
    key = f.read()
    f.close()

    IV = os.urandom(16)
    msg = pkcs7(msg)
    return cbc_encrypt(key, msg, IV), IV

def validate_token(msg, IV):
    f = open("key.key", "r")
    key = f.read()
    f.close()

    plaintext = cbc_decrypt(key, msg, IV)
    
    try:
        pkcs7_validate(plaintext)
        return True
    except:
        return False
    
main()


