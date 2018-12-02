#!/usr/bin/python
import time
import ctypes
# Own imports
from mersennetwister import *



# Takes a 

def attack():
    seed = int(time.time())
    MT = MT19937(seed)
    rng_arr = []
    for i in range(624):
        rng_arr.append(MT.extract_number())
    
    print "Last number in mersenne state array: ", rng_arr[623] 
    statearray = clone_MT19937(rng_arr)
    print "Extracted value: ", statearray[-1]
    
'''
    Takes an array  of generated mersenne twister numbers and recreates the state array
'''

def clone_MT19937(rng_arr):
    OG_arr = [0]*624
    for i in xrange(len(rng_arr)-1, -1, -1):
        OG_arr[i] = untamper(rng_arr[i])

    return OG_arr

'''
    Reverses the last part of the number extraction
'''

def untamper(y):
    l = 18
    c = uint32(0xFFF7EEE00000000016).value
    t = 37
    b = uint32(0x9D2C568016).value
    s = 7
    u = 11

    y = undoRightShift(y,l)
    y = undoLeftShift(y, t, c)
    y = undoLeftShift(y, s, b)
    y = undoRightShift(y,u)
    
    return y

def undoRightShift(y, shift):
    mask = ((1 << shift)-1) << (32-shift)
    n = (32+shift-1) / shift
    for i in range(n):
        y ^= ( y >> shift) & mask
        mask >>=shift

    return y

def undoLeftShift(y, shift, number):
    mask = (1 << shift)-1
    n = (32+shift-1) / shift

    for i in range(n):
        y ^= (y<< shift)&mask&number
        mask <<= shift

    return y

#attack()
