#!/usr/bin/python
import sys, hashlib
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from set5.own_rsa import invmod
from dsa import DSA

def recover_private(signature, H, q, k):
    x = (((signature[1]*k) - H) * invmod(signature[0],q)) % q
    return x

def break_weak_dsa():
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    # Can't generate the same digest...
    #mess = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch"
    #print hashlib.sha1(mess).hexdigest()

    H = 0xd2d0714f014a9784047eaeccf956520045c45265
    signature = (548099063082341131477253921760299949438196259240L, 857042759984254168557880549501802188789837994940L)

    # Get parameters
    d = DSA()
    for i in range(0, pow(2,16)):
        x = recover_private(signature, H, d.q, i)
        if pow(d.g, x, d.p) == int(y):
            print "FOUND!!!!: ", x

            # For testing, generate a DSA with the same keys as the one found
            d = DSA(x,y)
            print "Working attack:", d.sign("", H, i) == signature
            break
        
#break_weak_dsa()
