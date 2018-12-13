#!/usr/bin/python
import sys
from random import randint
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from dh import *
from set2.aescbc import *

def mitm_attack():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a, A = gen_public_keys(g,p)
    
    print "Server received:"
    print "p:", p
    print "g: ", g
    print "A:", A
    print ""
    
    print "Injection of three parameters"
    print "1. g = 1"
    print "2. g = p"
    print "g = p-1"
    print "" 
    print "First: "
    print "g=1 leads to B=1 since 1**b % p = 1"
    # Proof of work
    g = 1
    b, B = gen_public_keys(g,p)
    print "B == b:", B == 1
    print ""
    print "Second: "
    print "g=p leads to B=0. Since p**p % p = 0"
    # Proof of work
    g = p
    b, B = gen_public_keys(g,p)
    print "B == 0: ", B == 0
    print ""
    print "Third: "
    print "g=p-1 leads to B=1 if b is even and B = p-1 if b is odd"
    # Proof of work
    g = p-1
    b, B = gen_public_keys(g, p)
    print "B == 1", B == 1
    print "or..."
    print "B == p-1", B == p-1
    print ""
    print "Now the MITM has the crypto key, since It's just SHA1(b)[:32]"
mitm_attack()
