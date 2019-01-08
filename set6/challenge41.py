#!/usr/bin/python
import sys, json, time, binascii
sys.path.insert(0, r'/home/ludvig/cryptopals')
from hashlib import sha256
from random import randint

# Own imports
from set5.own_rsa import *

saved_hashes = []
def unpadded_recovery_oracle(rsa_blob, privkey):
    if sha256(str(rsa_blob)).hexdigest() in saved_hashes:
        return False
    saved_hashes.append(sha256(str(rsa_blob)).hexdigest())

    return decrypt(privkey, rsa_blob)
    
def main():
    pubkey, privkey = key_gen()
    m = json.dumps({'time': int(time.time()), 'social': '1111-1111'})
    # Prep m for RSA
    prepped = int("0x"+binascii.hexlify(m), 16)
    # Create a C and send it to the server once to append to the saved_hashes list
    c = encrypt(pubkey, prepped)
    tmp = unpadded_recovery_oracle(c, privkey)
    
    recovered = attack(c, pubkey, privkey)
    org_m = binascii.unhexlify(hex(recovered)[2:-1])
    print "RECOVERED: ", org_m

# Private key is not needed for the attack, but it's included for the unpadded recovery call
def attack(c, pubkey, privkey):
    s = randint(2, pubkey[1])
    c_prime = (pow(s, pubkey[0], pubkey[1])*c) % pubkey[1]
    p_prime = unpadded_recovery_oracle(c_prime, privkey)

    m = p_prime * invmod(s, pubkey[1]) 
    
    '''
        Math logic: 
            
            C' = (S**e % N)*C
            P' = P*(S**e % N)

            This means,

            P = P' / (S**e % N)

            Which is the same as,

            P = (P' * invmod(S, N)) % N
    '''
    return m % pubkey[1]
    
main()
