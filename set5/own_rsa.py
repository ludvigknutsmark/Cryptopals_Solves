#!/usr/bin/python
from Crypto.Util import number
import binascii

def key_gen():
    bit_len = 512
    while 1:
        p = number.getPrime(bit_len)
        q = number.getPrime(bit_len)
        N = p*q
        e_t = (p-1)*(q-1)
        e = 3
        try:
            d = invmod(e, e_t)
            break
        except:
            continue

    return [e, N], [d,N]

def encrypt(pubkey, m):
    return pow(m,pubkey[0], pubkey[1])

def decrypt(privkey, c):
    return pow(c,privkey[0], privkey[1])

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def invmod(e, N):
    g, x, y = egcd(e, N)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % N

def test():
    m = int("0x"+binascii.hexlify("Rollin' in my 5.0"), 16)
    pubkey, privkey = key_gen()

    c = encrypt(pubkey, m)
    print "Working? ", decrypt(privkey, c) == m

#test()
