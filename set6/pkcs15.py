#!/usr/bin/python
import os

class PKCS15():
    def __init__(self, k):
        if k % 8 != 0:
            raise ValueError('Key size must be a multiple of 8')
        self.k = k / 8
    
    def pad(self, D):
        if len(D) > self.k - 11:
            raise ValueError('Data to large')
        pad_len = self.k - 3 - len(D)
        ps = os.urandom(pad_len)
        EB_string = "\x00\x02"+ps+"\x00"+D
        EB = 0
        for by in EB_string:
            EB = EB*256+ord(by)
        
        return EB
