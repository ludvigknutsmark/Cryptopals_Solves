#!/usr/bin/python
import sys
from hashlib import sha256
from random import randint
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from dh import *
from set2.aescbc import *


def zero_key():
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3
    print "First attack: Change the public key to zero. Try to login with any password you want :-)"
    I = raw_input("Email>")
    P = raw_input("Password>")
    
    # S
    salt = randint(1,N)
    xH = sha256(str(salt)+"password").hexdigest()
    x = int('0x'+xH, 16)
    v = pow(g,x,N)

    # C -> S
    a,A = gen_public_keys(g,N)
    print "FIRST ATTACK: CHANGE A (Client public key to zero): "
    A = 0
    # send I, A

    # S -> C
    b, B = gen_public_keys(g,N)
    B += k*v
    # send salt, B
    
    # S AND C
    uH = sha256(str(A)+str(B)).hexdigest()
    u = int('0x'+uH, 16)

    # C
    xH = sha256(str(salt)+P).hexdigest()
    x = int('0x'+xH, 16)
    
    tmp = B-k * pow(g,x,N)
    cS = pow(tmp, (a+u*x), N)
    cK = sha256(str(cS)).hexdigest()
    
    # S
    tmp = A*pow(v,u,N) % N
    sS = pow(tmp,b,N)
    sK = sha256(str(sS)).hexdigest()
    
    # C
    toSend = hmac_sha256(cK, str(salt))
    print "FIRST ATTACK: A=0 gives server S = 0 and therefore the validation key the value of HMAC_SHA256(sha256(0), salt)"
    print "SET CLIENT VALIDATION KEY TO THIS VALUE"
    toSend = hmac_sha256(sha256(str(0)).hexdigest(), str(salt))
    print ""
    # S
    if hmac_sha256(sK, str(salt)) == toSend:
        print "SERVER VALIDATION TRUE"
    else:
        print "SERVER VALIDATION FALSE"
    print ""
def other_values():
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3
    print "Second attack: Get the client to send N, N*2, &c. Try to login with any password you want :-)"
    I = raw_input("Email>")
    P = raw_input("Password>")
    
    # S
    salt = randint(1,N)
    xH = sha256(str(salt)+"password").hexdigest()
    x = int('0x'+xH, 16)
    v = pow(g,x,N)

    # C -> S
    a,A = gen_public_keys(g,N)
    print "SECOND ATTACK: SET A=N*x where x is member of set N{0,1,2,3,...}"
    A = N*randint(0,N)
    # send I, A

    # S -> C
    b, B = gen_public_keys(g,N)
    B += k*v
    # send salt, B
    
    # S AND C
    uH = sha256(str(A)+str(B)).hexdigest()
    u = int('0x'+uH, 16)

    # C
    xH = sha256(str(salt)+P).hexdigest()
    x = int('0x'+xH, 16)
    
    tmp = B-k * pow(g,x,N)
    cS = pow(tmp, (a+u*x), N)
    cK = sha256(str(cS)).hexdigest()
    
    # S
    tmp = A*pow(v,u,N) % N
    sS = pow(tmp,b,N)
    sK = sha256(str(sS)).hexdigest()
    
    # C
    toSend = hmac_sha256(cK, str(salt))
    print "SECOND ATTACK: A=N*x where x is member of N,  gives server S=0, since N*x % N = 0 (Math is obvious), and therefore the validation key the value of HMAC_SHA256(sha256(0), salt)"
    print "SET CLIENT VALIDATION KEY TO THIS VALUE"
    toSend = hmac_sha256(sha256(str(0)).hexdigest(), str(salt))
    print ""
    # S
    if hmac_sha256(sK, str(salt)) == toSend:
        print "SERVER VALIDATION TRUE"
    else:
        print "SERVER VALIDATION FALSE"


def hmac_sha256(key, message):
    
    if len(key) > 128:
        key = sha256(key).hexdigest()

    if len(key) < 128:
        padding = b'\x00'*(128-(len(key)%128))
        key += padding

    o_key_pad = xor(list(key), [chr(int('0x5c', 16))]*128)
    i_key_pad = xor(list(key), [chr(int('0x36', 16))]*128)

    return sha256(o_key_pad + sha256(i_key_pad+message).hexdigest()).hexdigest()   

#zero_key()
#other_values()
