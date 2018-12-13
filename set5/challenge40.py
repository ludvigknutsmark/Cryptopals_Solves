#!/usr/bin/python
import gmpy2

# Own imports
from own_rsa import *

def broadcast_attack():
    m = int("0x"+binascii.hexlify("Ice ice baby"), 16)
    pubkey0, privkey0 = key_gen()
    pubkey1, privkey1 = key_gen()
    pubkey2, privkey2 = key_gen()

    c0 = encrypt(pubkey0, m)
    c1 = encrypt(pubkey1, m)
    c2 = encrypt(pubkey2, m)

    m_s_0 = pubkey1[1]*pubkey2[1]
    m_s_1 = pubkey0[1]*pubkey2[1]
    m_s_2 = pubkey0[1]*pubkey1[1]

    result = (c0*m_s_0*invmod(m_s_0, pubkey0[1]))+(c1*m_s_1*invmod(m_s_1, pubkey1[1]))+(c2*m_s_2*invmod(m_s_2, pubkey2[1]))
    calc_m = result % (pubkey0[1]*pubkey1[1]*pubkey2[1])
    ans = calc_m**(1./3.)
    print "RECOVERED M: ", ans
    print "CALCULATED CORRECT: ", str(ans) == str(float(m))
    
    


broadcast_attack()
