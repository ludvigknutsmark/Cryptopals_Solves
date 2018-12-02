#!/usr/bin/python
import sys, os, base64, binascii
sys.path.insert(0, r'/home/ludvig/cryptopals')
from collections import OrderedDict
from operator import itemgetter

# Own imports
from set2.aescbc import *

# Breaks a repeating XOR. If you want the guessing key length algorithm included check set1/main.py.
# This takes a specified key_length
def break_repeatingxor(msg, key):
    blocks = []
    for i in range(len(msg)/key):
        blocks.append(msg[i*key:(i+1)*key])
   
    sb_blocks = []
    for k in range(key):
        transposed = ""
        for b in blocks:
            transposed += b[k]
        sb_blocks.append(SB_xor(transposed))

    # sb_blocks[i] is same as the block of all i characters in each block
    
    plaintext = ""
    for block in sb_blocks:
        block_txt = ""
        for j in range(key):
            try:
                block_txt += sb_blocks[j][i]    
            except:
                pass
        plaintext += block_txt 
    
    return plaintext

# Calculates the hamming distance between two strings
def hamming(msg1, msg2):
    diff = 0
    if len(msg1) != len(msg2):
        raise ValueError('Lengths does not match')

    for i in range(len(msg1)):
        b1 = ord(msg1[i])
        b2 = ord(msg2[i])
        
        for j in range(8):
            mask = int(bytes(1 << j))
            if (b1&mask) != (b2&mask):
               diff += 1
    return diff

# Calculates the best scoring text for the XOR key
def SB_xor(src):
    max_score = 0
    eng_text = ""
    for i in range(255):
        xor_list = []
        for k in src:
            xor_list.append(chr(i))
        
        text = xor(list(src), xor_list)
        score = set_score(text)
        
        if score > max_score:
            max_score = score
            eng_text = text
    
    return eng_text

# Advanced english scoring algorithm ;)
def set_score(src):
    freq = {}
    freq[' '] = 700000000
    freq['e'] = 390395169
    freq['t'] = 282039486
    freq['a'] = 248362256
    freq['o'] = 235661502
    freq['i'] = 214822972
    freq['n'] = 214319386
    freq['s'] = 196844692
    freq['h'] = 193607737
    freq['r'] = 184990759
    freq['d'] = 134044565
    freq['l'] = 125951672
    freq['u'] = 88219598
    freq['c'] = 79962026
    freq['m'] = 79502870
    freq['f'] = 72967175
    freq['w'] = 69069021
    freq['g'] = 61549736
    freq['y'] = 59010696
    freq['p'] = 55746578
    freq['b'] = 47673928
    freq['v'] = 30476191
    freq['k'] = 22969448
    freq['x'] = 5574077
    freq['j'] = 4507165
    freq['q'] = 3649838
    freq['z'] = 2456495

    score = 0    
    for i in src:
        try:
            score += freq[i]
        except:
            pass

    return score
