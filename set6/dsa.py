#!/usr/bin/python
import sys, hashlib
from random import randint
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from set5.own_rsa import invmod


class DSA():
    def __init__(self, private=None, public=None, g=None):
        self.p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
        self.q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        
        if g == None:
            self.g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
        else:
            self.g = g

        # Ugly code, but only for testing purposes
        if private == None:
            self.privatekey = randint(0, self.q)
        else:
            self.privatekey = private
        if public == None:
            self.publickey = pow(self.g,self.privatekey,self.p)
        else:
            self.publickey = public

    def sign(self, mess, H=None, k=None):
        if k == None:
            k = randint(1, self.q)
        r = pow(self.g, k, self.p) % self.q
        if r == 0:
            return self.sign(self, mess)
        
        k_inv = invmod(k, self.q)
        if H == None:
            H = int("0x"+hashlib.sha1(mess).hexdigest(), 16)
        
        s = k_inv*(H+self.privatekey*r) % self.q
        if s == 0:
            return self.sign(self, mess)
        
        return (r,s)
    
    def verify(self, signature, mess):
        if isinstance(signature, tuple) == False:
            raise ValueError("Signature is not a tuple")

        r = signature[0]
        s = signature[1]
        
        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False
        
        w = invmod(s, self.q)         
        H = int("0x"+hashlib.sha1(mess).hexdigest(), 16)
        u_1 = H*w % self.q
        u_2 = r*w % self.q

        v = (pow(self.g, u_1, self.p)*pow(self.publickey, u_2, self.p) % self.p) % self.q
        return v == r
