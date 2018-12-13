#!/usr/bin/python
import sys
from random import randint
from hashlib import sha256
sys.path.insert(0, r'/home/ludvig/cryptopals')

# Own imports
from dh import *
from challenge37 import hmac_sha256

# Small values to test
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

def simulation(): 
    password = raw_input("Password>")
    # S
    salt = randint(1, N)
    xH = sha256(str(salt)+"test").hexdigest()
    x = int('0x'+xH, 16)
    v = pow(g, x, N)

    # C
    # diffie-hellman key generation
    a,A = gen_public_keys(g, N)

    # MITM
    b, B = gen_public_keys(g, N)
    u = randint(pow(2,127), pow(2,128)-1)
    print ""
    print "ATTACK: set u=1 so cS= (B**a)*(B**x). B = g so (B**a)==(g**a). Salt can be any arbitrary value.\n"
    # Attack
    u = 1
    B = 2
    salt = 1

    # C
    xH = sha256(str(salt)+password).hexdigest()
    x = int('0x'+xH, 16)
    cS = pow(B, (a+u*x), N)
    cK = sha256(str(cS)).hexdigest()
    
    # S 
    tmp = A*pow(v,u,N) % N
    sS = pow(tmp, b, N)
    sK = sha256(str(sS)).hexdigest()

    # C
    toSend = hmac_sha256(cK, str(salt))
    print "Client validation key: ", toSend
    # Server validation
    if hmac_sha256(sK, str(salt)) == toSend:
        print "Authorized :)"
    else:
        print "Not authorized :("
    
    # For challenge purposes return the target hmac and the A value :)
    return A, toSend

def attack(A, target):
    f = open("commonpasswords.txt", "r")
    passwordlist = f.readlines()
    f.close()
    print "\nStarting attack:"
    print "Calculating...."
    password = None
    for guess in passwordlist:
        guess = guess.rstrip() #remove trailing newline
        xH = sha256(str(1)+guess).hexdigest()
        x = int('0x'+xH, 16)
        tmp = A*pow(2,x,N) % N
        cS = sha256(str(tmp)).hexdigest()
        cK = hmac_sha256(cS, str(1))
        if cK == target:
            print "PASSWORD FOUND: ", guess
            print "PASSWORD FOUND: ", guess
            print "PASSWORD FOUND: ", guess
            password = guess
            break
    if password == None:
        print "No password found, sorry :("

print "Math logic: if we give the user u=1 the clients validation key will be hmac(S, salt) where S \
is B**(a+ux). u=1 gives S=B**(a+x) which is the same as S=(B**a)*(B**x). Recognize (B**a)? It's A, if B==g, (the public key from the user. Which the attacker knows). After that the attack is simply a dictionary attack using the top 10000 most common passwords\n"

A, target = simulation()
attack(A, target)
