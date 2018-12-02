#!/usr/bin/python
import sys,struct,time, os
from random import randint
import datetime
sys.path.insert(0, r'/home/ludvig/cryptopals')

#Own imports
from mersennetwister import *
from set2.aescbc import xor

class MT19937_StreamCipher(object):
    def __init__(self, key, src):
        self.randtapper = MT19937(key)
        
        # Maybe a stupid solution as you need to initialize with a plaintext aswell..
        self.keystream = ""
        keystream_len = len(src)/8
        for i in range(keystream_len):
            rand = self.randtapper.extract_number()
            self.keystream += struct.pack('<Q', rand)
        rest = len(src)%8
        if rest != 0:
            self.keystream += struct.pack('<Q', self.randtapper.extract_number())

    def cipher(self, src):
        return xor(list(src), list(self.keystream))

def gen_password_reset_token():
    key = int(time.time())
    mt = MT19937(key)
    return struct.pack('<Q', mt.extract_number())

def validate_token(reset_token):
    # Check if the token is validated within the last hour
    curtime = int(time.time())
    lastHour = datetime.datetime.now() - datetime.timedelta(hours = 1)
    start = int(time.mktime(lastHour.timetuple()))
    
    for i in xrange(start, curtime):
        mt = MT19937(i)
        if mt.extract_number() == struct.unpack('<Q', reset_token)[0]:
            return True
    
    return False

def main():
    key = pow(2,16)
    prepend = os.urandom(randint(4,12))
    src = prepend + "A"*14
    streamCipher = MT19937_StreamCipher(key, src)
    cipher = streamCipher.cipher(src)

    # Checking if the stream cipher works
    print "WORKING STREAM CIPHER:", streamCipher.cipher(cipher) == src

    # Known plaintext attack, I know the first 14 bytes are A which means I can get a number in the mersenne twister state array
    
    # First number is a special case so don't mind that
    idx_to_start = len(cipher)-(len(cipher)%8) 
    # Take the second number instead
    temp = xor(list(cipher[idx_to_start-8:idx_to_start]), list("A"*8))
    y = struct.unpack('<Q', temp)[0]
    print "UNTAMPERED VALUE:", y
    
    # Bruteforce the key until we find the untampered value above
    for i in xrange(45000, pow(2,16)+1):
        streamCipher = MT19937_StreamCipher(i, "A"*len(cipher))
        cipher = streamCipher.cipher("A"*len(cipher))

        idx_to_start = len(cipher)-(len(cipher)%8)
        temp = xor(list(cipher[idx_to_start-8:idx_to_start]), list("A"*8))
        if struct.unpack('<Q', temp)[0] == y:
            print "FOUND KEY: ", i
    
    # Generate a token and check if It's been generated within the last hour 
    token = gen_password_reset_token()
    time.sleep(1)
    print "VALIDATE TOKEN: ", validate_token(token)

main()
