#!/usr/bin/python
import sys
sys.path.insert(0, r'/home/ludvig/cryptopals')
from random import randint

# Own imports
from pkcs15 import PKCS15
from set5.own_rsa import *

def main():
    pk = PKCS15(256)
    # Pad the message according to PKCS1.5 standard
    m = pk.pad("kick it, CC")
    # Generate key for RSA
    pubkey, privkey = key_gen(256)
    c = encrypt(pubkey, m)
    # Send the ciphertext to the validation oracle
    print "VALIDATED:", validation_oracle(c, privkey)
    print "Starting attack...."
    attack(c, pubkey, privkey)

def validation_oracle(c, privkey):
    p_l = decrypt(privkey, c)
    p = nstr(p_l)
    if p[0] == "\x02":
        return True
    
    return False

def attack(c, pubkey, privkey):
    N = pubkey[1]
    B = (256-2)/8
    M = []
    S = []
    while 1:
        s = randint(2, 256*8)
        s_e = encrypt(pubkey, s)
        c0 = c*s_e % N
        if validation_oracle(c0, privkey):
            M.append([2*B, 3*B-1])
            i = 1
            S.append(s)
            break
    print S
    '''
    if i == 1:
        lim = N/(3*B)
        while 1:
            s1 = lim
            s1_e = encrypt(pubkey, s1)
            c0 = c*s1_e % N
            if validation_oracle(c0, privkey) and s1 != S[0]:
                S.append(s1)
                break
            lim+=1
    ''' 
    print M
    # Starting the interval search
    # Step 2c
    i = 1
    a = M[i-1][0]
    b = M[i-1][1]
    if a != b: 
        lim = b*S[i-1]-2*B
        print lim


def nstr(n):
    h=hex(n)[2:]                        # remove 0x prefix
    if h[-1:]=='L': h=h[:-1]            # remove L suffix if present
    if len(h)&1: h="0"+h
    return binascii.unhexlify(h)

main()
