#!/usr/bin/python
import sys, hashlib
from itertools import combinations
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from set5.own_rsa import invmod
from dsa import DSA
from challenge43 import recover_private

def main():
    d = DSA()
    
    f = open("44.txt", "r")
    text = f.readlines()
    f.close()
    
    groups = []
    for i in range(len(text)/5+3):
            groups.append(text[i*4:(i+1)*4])
            
    # We know the k is repeated if r is the same, since r only depends on static parameters and k
    # 1st and 9th has the same r.
    first = groups[0]
    second = groups[8]

    r1 = int(first[2][3:-1])
    r2 = int(second[2][3:-1])

    s1 = int(first[1][3:-1])
    s2 = int(second[1][3:-1])

    m1 = int(first[3][3:-1], 16)
    m2 = int(second[3][3:-1], 16)

    nom = (m1-m2)%d.q
    denom = (s1-s2)%d.q
    k = (nom * invmod(denom, d.q)) % d.q
    signature = (r1,s1)
    x = recover_private(signature, m1, d.q, k)
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    
    print "Private key found: ", pow(d.g, x, d.p) == int(y)
    print "Private SHA1: ", hashlib.sha1(hex(x)[2:-1]).hexdigest()
    print "Correct private found: ", hashlib.sha1(hex(x)[2:-1]).hexdigest() == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

    '''
        Math logic:
            
            s1 = (m1+xr) / k
            s2 = (m2+xr) / k

            And since x is unknown to the attacker, we can't calculate k from a single signature.
            But since k is reused we know that xr/k is the same for both signatures, which means that

            k = (m1-m2) / (s1-s2)
    '''
main()
