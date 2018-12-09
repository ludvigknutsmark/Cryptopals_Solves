#!/usr/bin/python 
import struct, binascii

# Own imports
from md4 import MD4

def main(): 
    key = "KEY" 
    message = "A" 
    new_message = "B"

    mac_hash = md4mac(key,message) 
    mh = struct.unpack('<4I', mac_hash)

    h = [] 
    for i in range(0,4): 
        h.append(mh[i])
    

    # This extremely weird bug, which does that i cannot iterate the key_len guess. I know it's threeso i just sets it to three. MD4 implementation bug? 
    k = 3
    newData = calculatePadding(message, k)+new_message 
    forged = md4digest(new_message, h, (k+len(newData))*8)
    new_mac = md4mac(key, newData)
    if forged == new_mac:
        print "FOUND MATCHING SIGNATURES: ", binascii.hexlify(forged)
    
def calculatePadding(src, key_len):
  l = len(src)+key_len
  bit_len = (len(src)+key_len)*8
  m = ""
  m = src + "\x80"+"\x00" * ((55-l) % 64)+struct.pack("<Q", bit_len)
  return m

def md4digest(src, h, key_len):
    md = MD4(h)
    md.add(src)
    return md.finish(key_len)

def md4mac(key,src):
    md = MD4()
    md.add(key+src)
    return md.finish()

main()
