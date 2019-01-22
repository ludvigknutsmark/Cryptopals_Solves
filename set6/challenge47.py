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
    print m
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


def getNextS(M, pubkey, privkey, N, s, c, B):
    a = M[0][0]
    b = M[0][1]
    ri = (2*(b*s-2*B)+N-1) // N
    while 1:
        b_lim = (2*B+ri*N+b-1) // b
        a_lim = (3*B+ri*N+a-1) // a
        for si in range(b_lim, a_lim):
            c0 = c*encrypt(pubkey, si) % N
            if validation_oracle(c0, privkey):
                return si
        ri += 1

def computeNewM(M, N, s, B):
    a = M[0][0]
    b = M[0][1]
    r_interval = [(a*s-3*B+1+N-1) // N, (b*s-2*B) // N]
    if r_interval[0] > r_interval[1]:
        print "ERROR"
        sys.exit(0)
    ri = r_interval[0]
    low = max(a, (2*B+ri*N+s-1)//s)
    upper = min(b, (3*B-1+ri*N)//s)
    if low > upper:
        print "ERROR"
        sys.exit(0)

    return [[low, upper]]

def attack(c, pubkey, privkey):
    N = pubkey[1]
    k = (256+7)//8
    B = pow(2,8*(k-2))
    M = [[2*B, 3*B-1]]
    S = []
    R = [0]

    # Get first S
    # Step 2a
    s = (N+3*B-1)//(3*B)
    while 1:
        s1_e = encrypt(pubkey, s)
        c0 = (c*s1_e) % N
        if validation_oracle(c0, privkey):
            S.append(s)
            break
        s+=1
    
    s = S[0]
    M = computeNewM(M, N, s, B)
    
    while True:
        if M[0][0] == M[0][1]:
            m = M[0][0]
            print "FOUND", m
            try:
                print nstr(m)
            except:
                print "ERROR"
            break

        s = getNextS(M, pubkey, privkey, N, s, c, B)
        M = computeNewM(M,N, s,B)

def nstr(n):
    h=hex(n)[2:]                        # remove 0x prefix
    if h[-1:]=='L': h=h[:-1]            # remove L suffix if present
    if len(h)&1: h="0"+h
    return binascii.unhexlify(h)

main()
