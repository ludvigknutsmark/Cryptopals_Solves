#!/usr/bin/python
import sys, time
from timeit import default_timer as timer
sys.path.insert(0, r'/home/ludvig/cryptopals')

#Own imports
from sha1 import sha1
from set2.aescbc import xor


def main():

    url = "http://test?file=foo"
    hex_chrs = "0123456789abcdef"
    print "CORRECT S: ", hmac_sha1(b'key', "foo")

    signature_guess = ""
    for k in range(40):
        time_dict = {}
        signature = ""

        for i in hex_chrs:
            signature = signature_guess+i
            url_sig = url+"&signature="+signature
            start = timer()
            # Cheating with the k offset, but without it the wait time is long..
            verify_file_signature(url_sig, k)
            end = timer()
            time_dict[i] = end-start
        
        signature_guess += max(time_dict, key=time_dict.get)

    print "MY GUESS S: ",signature_guess
    print "Working attack?:", signature_guess==hmac_sha1(b'key', "foo")

def hmac_sha1(key, message):
    
    if len(key) > 64:
        key = sha1(key)

    if len(key) < 64:
        padding = b'\x00'*(64-(len(key)%64))
        key += padding

    o_key_pad = xor(list(key), [chr(int('0x5c', 16))]*64)
    i_key_pad = xor(list(key), [chr(int('0x36', 16))]*64)

    return sha1(o_key_pad + sha1(i_key_pad+message))

def verify_file_signature(url, offset=0):
    key = b'key'    

    # Contains no fault handling whatsoever :-)
    file_str = "?file="
    name_idx = url.find(file_str)+len(file_str)
    sig_str = "&signature="
    sig_idx = url.find(sig_str)

    filename = url[name_idx:sig_idx]
    signature = url[sig_idx+len(sig_str):]

    server_signature = hmac_sha1(key, filename)
    
    # Insecure compare function
    for i in range(offset, len(signature)):
        if signature[i] != server_signature[i]:
            return False

        time.sleep(0.005)
        
    return True
    

main()
