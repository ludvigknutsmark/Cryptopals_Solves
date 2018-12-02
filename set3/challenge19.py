import base64, struct
from collections import OrderedDict
from operator import itemgetter

# Own imports
from aes_ctr import *

def main():
    encrypted = []
    f = open("challenge19_plaintexts.txt", "r")
    plaintexts = f.readlines()
    f.close()

    for i in plaintexts:
        encrypted.append(encrypt(i))
    
    freq_list = []
    freq_dict = {}

    for cipher in encrypted:
        for i in cipher:
            freq_dict[ord(i)] = 0

    for cipher in encrypted:
        for i in cipher:
            if ord(i) in freq_list:
                freq_dict[ord(i)] += 1
            else:
                freq_list.append(ord(i))
    
    ordered = OrderedDict(sorted(freq_dict.items(), key=itemgetter(1), reverse = True))
    

    ETAOIN = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    ordered_string = []
    for i in ordered:
        ordered_string.append(i)

    decoded = ""
    for cipher in encrypted:
        for i in cipher:
            etaoin_index = ordered_string.index(ord(i))
            try:
                decoded += ETAOIN[etaoin_index]
            except:
                decoded += '?'

    print decoded

def encrypt(msg):
    f = open("key.key", "r")
    key = f.read()
    f.close()

    Nonce = struct.pack('<Q', 0)

    plaintext = base64.b64decode(msg)
    return aes_ctr(key, Nonce, plaintext)

main()
