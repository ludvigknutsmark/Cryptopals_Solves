#!/usr/bin/python
# STOLEN FROM https://gist.github.com/bonsaiviking/5644414
import struct, binascii

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, ownH=None):
        self.remainder = ""
        self.count = 0
        if ownH == None:
            self.h = [
                    0x67452301,
                    0xefcdab89,
                    0x98badcfe,
                    0x10325476
                    ]
    
        else:
            self.h = ownH
    def _add_chunk(self, chunk):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def finish(self, additionalLen=None):  
        l = len(self.remainder) + 64 * self.count
        
        if additionalLen != None:
            bit_len = additionalLen
        else:
            bit_len = l*8
            
        self.add( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", bit_len))
        out = struct.pack("<4I", *self.h)
        self.__init__()
        return out

