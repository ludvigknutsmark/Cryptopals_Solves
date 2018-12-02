#!/usr/bin/python
import base64, struct
from collections import OrderedDict
from operator import itemgetter

# Own imports
from aes_ctr import *
from xorfuncs import *

def main():
    encrypted = []
    f = open("challenge20_plaintexts.txt", "r")
    plaintexts = f.readlines()
    f.close()

    for i in plaintexts:
        encrypted.append(encrypt(i))

    # Pick out the shortest length    
    shortest_len = 300
    for cipher in encrypted:
        if len(cipher) < shortest_len:
            shortest_len = len(cipher)
    
    # Truncate to shortest_len
    truncated = ""
    for cipher in encrypted:
        truncated += cipher[:shortest_len]
    
    # Break the repeating XOR key with the key length of shortest_len
    # Calculates the best scoring english text after ETAOIN SHRTULT thingy
    print break_repeatingxor(truncated, shortest_len)

def encrypt(msg):
    f = open("key.key", "r")
    key = f.read()
    f.close()

    Nonce = struct.pack('<Q', 0)

    plaintext = base64.b64decode(msg)
    return aes_ctr(key, Nonce, plaintext)

main()
