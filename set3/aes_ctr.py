import sys, os, struct
from Crypto.Cipher import AES
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from set2.aescbc import xor # XOR function

def gen_keystream(key, counter):
    cipher = AES.new(key)
    return cipher.encrypt(str(counter))

def aes_ctr(key, nonce, plaintext):
    # Create the counter bytes
    counter = struct.pack('<Q', 0)
    dst = ""
    # Save the number of iterations so we can start from the rest
    block_iteration = 0
    
    # Whole 16 byte blocks
    for i in range(len(plaintext)/16):
        keystream = gen_keystream(key, nonce+counter)
        dst += xor(list(plaintext[i*16:(i+1)*16]), list(keystream))
        counter = struct.pack('<Q', i+1)
        block_iteration += 1
    
    # The rest of the plaintext
    rest = len(plaintext) % 16
    if rest != 0:
        keystream = gen_keystream(key, nonce+counter)
        dst += xor(list(plaintext[block_iteration*16:]), list(keystream))

    return dst

