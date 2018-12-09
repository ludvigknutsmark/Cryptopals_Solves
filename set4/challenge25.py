#!/usr/bin/python
import sys, base64, struct
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from set3.aes_ctr import *
from set2.aescbc import xor

def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    # Get the plaintexy
    f = open("challenge25_plaintext.txt", "r")
    plaintext = f.read()
    f.close()

    nonce = struct.pack('<Q', 0)

    # Encrypt the plaintext
    og_ciphertext = encrypt(plaintext, key, nonce)
    og_plaintext = ""
    
    # Recover the keystream for each block by adding a known plaintext (A's) and XOR the keystream with the ciphertext to recover the plaintext :-)
    for i in range(len(og_ciphertext)/16):
        n_ciphertext = edit(og_ciphertext, key, nonce, 0, "A"*(i+1)*16)
        keystream = xor(list(n_ciphertext[i*16:(i+1)*16]), list("A"*16))
        og_plaintext += xor(list(og_ciphertext[i*16:(i+1)*16]), list(keystream))

    print og_plaintext

    print "Recovered successfully: ", og_plaintext==plaintext

def encrypt(plaintext, key, nonce):
    return aes_ctr(key, nonce, plaintext)

def edit(ciphertext, key, nonce, offset, newtext):
    newcipher = aes_ctr(key, nonce, newtext)
    cipher = list(ciphertext)
    
    for i in range(len(newcipher)):
        cipher[i+offset] = newcipher[i]

    return ''.join(cipher)
    
main()
