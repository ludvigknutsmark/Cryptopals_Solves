#!/usr/bin/python

import os
from sha1 import sha1
def main():
    key = os.urandom(12)
    msg = "YELLOW SUBMARINE"

    og_hash = mac(key, msg)
    
    # Tamper the message a little bit..
    tampered = list(msg)
    tampered[1] = "X"
    tampered[2] = "Y"

    print "VALIDATE TAMPERED: ", mac(key, ''.join(tampered)) == og_hash


def mac(key, msg):
    # Convert to raw bytes
    bytedata = str.encode(msg)
    return sha1(key+bytedata)

#main()
