#!/usr/bin/python
import struct
# Own imports
from sha1 import sha1

def main():
    
    f = open("key.key")
    key = f.read()
    f.close()
    
    #message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    #new_message = b';admin=true'
    message = "A"
    new_message = "B"
    mac_hash = sha1(key+message)
   
    h = ()
    # Pick out the digest values
    for i in range(0, 5):
        h += (int('0x'+mac_hash[i*8:(i+1)*8], 16), )
    
    # Bruteforce the key length until a match is found
    for i in range(16,17):
        newData = calculatePadding(message, i)+new_message
        forged = sha1(new_message, h, (i+len(newData))*8)
        new_mac = sha1(key+newData)
        if forged == new_mac:
            print "FOUND MATCHING SIGNATURES: ", forged, " NEW DATA: ", list(newData), " KEY-LEN: ",i

def calculatePadding(src, key_len):
    message_byte_len = len(src)
    message = src
    message += b'\x80'
    message += b'\x00' * ((56 - (message_byte_len+key_len+1) % 64) % 64)
    # Quick fix to fix the remaining of the padding
    
    
    if(len(src)%64>=56):
        while len(message) != 120:
            message += b'\x00'
    
    bit_len = (message_byte_len+key_len)*8
    message += struct.pack(b'>Q', bit_len)   
    return message

main()
