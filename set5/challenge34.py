#!/usr/bin/python
import sys
from random import randint
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from dh import *
from set2.aescbc import *

def test_implementation():

    # Alice -> Bob
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    a, A = gen_public_keys(g,p)
    keys = [p, g, A]
    print "A -> B: ", keys

    # Bob -> Alice
    b, B = gen_public_keys(keys[1], keys[0])
    print "B -> A: ", B

    # Alice -> Bob
    IV = bytearray(16)
    akey = gen_session_key(p,g,a,B)
    akey_byte = bytearray.fromhex('{:8x}'.format(int('0x'+akey, 16)))
    ciphertext = cbc_encrypt(str(akey_byte), "YELLOW SUBMARINE", IV)
    print "A -> B: ", ciphertext, IV

    
    # Bob -> Alice
    IV = bytearray(16)
    bkey = gen_session_key(p,g,b,A)
    bkey_byte = bytearray.fromhex('{:8x}'.format(int('0x'+bkey, 16))) 
    ciphertext = cbc_encrypt(str(bkey), "YELLOW SUBMARINE", IV)
    print "B -> A: ", ciphertext, IV

    # Control value
    plaintext = cbc_decrypt(akey, ciphertext, IV)
    print plaintext
    

def mitm_attack():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a, A = gen_public_keys(g,p)
    
    print "Server received:"
    print "p:", p
    print "g: ", g
    print "A:", A
    print ""
    print "MITM sends: p, g, p"
    
    # Bob's keys
    b, B = gen_public_keys(g,p)
    print ""
    print "Server received: "
    print "B:", B
    print ""
    print "MITM sends: p"

    # Alice
    IV = bytearray(16)
    akey = gen_session_key(p,g,a,p)
    akey_byte = bytearray.fromhex('{:8x}'.format(int('0x'+akey, 16)))
    ciphertext = cbc_encrypt(str(akey_byte), "YELLOW SUBMARINE", IV)
    print ""
    print "Server receives: "
    print "Ciphertext: ", ciphertext

    print "Server decryption: "
    # I know that the key from DH is zero. So I just hash the zero which is the generated key.
    '''
        Attack -> I Replace the public keys A and B with p.
        Math -> private_key = p**a % p = 0
        
        So the private key always becomes zero

    '''

    guess_key = sha1(bytearray(1))[:32]
    gkey_byte = bytearray.fromhex('{:8x}'.format(int('0x'+guess_key, 16)))
    guess_plaintext = cbc_decrypt(str(gkey_byte), ciphertext, IV) 
    print "Plaintext: ", guess_plaintext

#test_implementation()
mitm_attack()
