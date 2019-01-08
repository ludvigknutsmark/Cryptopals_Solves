#!/usr/bin/python
import sys, binascii, os, struct
sys.path.insert(0, r'/home/ludvig/cryptopals')
from hashlib import sha256
from random import randint
# Own imports
from set5.own_rsa import *

def main():
    pubkey, privkey = key_gen()
    msg = sha256("hi mom").digest()
    s = sign(msg, privkey)
    print "Working sig:", ver_sign(s, pubkey, msg)
    print ""
    print "Starting attack: "
    a = attack(msg)
    print "Working attack: ", ver_sign(a, pubkey, msg)

def attack(msg):
    #while 1:
    octet = "\x00\x01\xff\x00"+msg
    octet += "\x00"*(128-len(octet))
    target = 0
    for by in octet:
        target = target*256 + ord(by)

    attack_val = find_cube_root(target)
    print "Forged signature: ", attack_val
    return attack_val
    
def sign(m, privkey):
    # Pad the message
    N = privkey[1]
    block = ""
    if len(m) > (N.bit_length()/4)-11:
        raise ValueError('Message to long')
    
    block += "\x00\x01"
    for i in range((N.bit_length()/8)-(11+len(m))):
        block += "\xff"
    block+="\x00"+m
    return decrypt(privkey, strn(block))

def ver_sign(c, pubkey, target):
    N = pubkey[1]
    m = encrypt(pubkey, c)
    octet = nstr(m)
    # Check the valid padding too : - )
    if octet[:2] == "\x01\xff" and "\x00"+target not in octet:
        return False
    else:
        return True

def nstr(n):
    h=hex(n)[2:]                        # remove 0x prefix
    if h[-1:]=='L': h=h[:-1]            # remove L suffix if present
    if len(h)&1: h="0"+h
    return binascii.unhexlify(h)

def strn(s):
    return long(binascii.hexlify(s),16)

# Shamelessy stolen because my val**(1./3.) broke and I was tired
def find_cube_root(n):
    """Finds the cube root of n using binary search."""
    lo = 0
    hi = n
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid

    return lo

main()
