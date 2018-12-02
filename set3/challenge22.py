#!/usr/bin/python
import time
from random import randint

# Own imports
from mersennetwister import *

def routine():
    random_second = randint(2, 50)
    time.sleep(random_second)
    MT = MT19937(int(time.time()))
    time.sleep(randint(2,50))
    return MT.extract_number()


def crack_MT19937(rng):
    #Ish max wait time
    start_val = int(time.time()-101)

    for seed in xrange(start_val, int(time.time())):
        MT = MT19937(seed)
        rand = MT.extract_number()
        if rand == rng:
            print "FOUND THE SEED: ", seed
            break

crack_MT19937(routine())
