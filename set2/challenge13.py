# -*- coding: utf-8 -*-
# Common imports
import json

# Own imports
from cookieparser import *
from aesecb import *

def main():
    f = open("key.key", "r")
    key = f.read()
    f.close()
    
    #Create the user profile
    #email = "test@test.se"
     #plaintext = profile_for(email)   
    # ciphertext = ecb_encrypt(key, plaintext)

    # print ciphertext, len(ciphertext)

    ecb_attack(key)

def ecb_attack(key):
    # Find blocksize
    ciphertext = ""
    for i in range(20):
        email = "A@"+"A"*i
        plaintext = profile_for(email, "user")
        old_ciphertext = len(ciphertext)
        ciphertext = ecb_encrypt(key, plaintext)
        if len(ciphertext) != old_ciphertext and old_ciphertext > 0:
            print "Blocksize=", len(ciphertext)-old_ciphertext
     

    mail = "AAAAA,\"uid\":12,\"role\":\"admin\"}"
    role = "user"
    ciphertext = encrypt_user_profile(mail,role, key)
    role_admin = ciphertext[16:48]
    c_list = list(ciphertext)
    ad_list = list(role_admin)

    for i in range(48,80):
        c_list[i] = ad_list[i-48]
    ciphertext =  ''.join(c_list)
     
    user = decrypt_user_profile(ciphertext, key)
    print user[:79] 

def encrypt_user_profile(mail, role, key):
    user = profile_for(mail, role)
    print user[16:48], ":", len(user[16:48])
    return ecb_encrypt(key, user)

def decrypt_user_profile(ciphertext, key):
    return ecb_decrypt(key, ciphertext)

main()
