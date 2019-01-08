#!/usr/bin/python
import sys, base64
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from set5.own_rsa import *

def parity_oracle(msg, privkey):
    if decrypt(privkey, msg) % 2 == 0:
        return False
    
    return True

def main():
    pubkey, privkey = key_gen()  
    plain = base64.b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    m = int("0x"+binascii.hexlify(plain), 16)
    ciphertext = encrypt(pubkey, m)
    print bin(ciphertext)

    guess = ""
    N = pubkey[1]
    UB = N
    LB = 0
    for i in range(len(bin(ciphertext))):
        ciphertext *= pow(2,pubkey[0], N)
        parity = str(int(parity_oracle(ciphertext, privkey)))
        if parity == "0":
            UB = (UB+LB)/2
        else:
            LB = (UB+LB)/2
        try: 
            print binascii.unhexlify(hex(UB)[2:-1])
        except:
            pass

main()
