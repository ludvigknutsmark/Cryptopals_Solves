#!/usr/bin/python
import sys
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from dsa import DSA

def main():
    '''
        Since the algorithm (as specified by wikipedia), doesn't allow r=0 we swap the g to a 1 (theattack works the same). The verify parameter v becomes 1 (since both the publickey, y=1 and r=1)
    '''
    d = DSA(None, None, 1)
    d2 = DSA(None, None, 1)

    bad_signature = d.sign("bad")
    print bad_signature
    print "Verified with wrong keys: ", d2.verify(bad_signature, "otherstring")

    '''
        g = p+1 leads to the same attack as above as r == g**k % p and if g == p+1, r equals 1
    '''
    
    bad_2 = DSA(None, None, d.p+1)
    hello_world_sig = bad_2.sign("Hello, world")
    goodbye_world_sig = bad_2.sign("Goodbye, world")
    
    print "Hello world: ", hello_world_sig
    print "Goodbye, world: ", goodbye_world_sig
    print "Verified with wrong keys: ", bad_2.verify(hello_world_sig, "akdspfoas")
main()
