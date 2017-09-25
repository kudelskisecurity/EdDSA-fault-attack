#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import random
import sys
import getopt
import os

from eddsafault import publickey, signature, checkvalid, signwithfault, recovera, signwitha, H, bytes_to_clamped_scalar
from binascii import unhexlify

determinist = False
seedlen = 32
l = 2**252 + 27742317777372353535851937790883648493
offset = 5
errval = 23

def printHelp():  
    print("usage: " + sys.argv[0] + " [-h] [-r | -d] [-o <offset] [-e <error>]")
    print("options:")
    print("-r               launch a random simulation")
    print("-d               launch a deterministic simulation")
    print("")
    print("optional arguments:")
    print("-h, --help       show this help message and exit")
    print("-o               define the offset for the fault")
    print("-e               define the error value")

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        printHelp()
        sys.exit()
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hrdo:e:")
    except getopt.GetoptError:
        printHelp()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            printHelp()
            sys.exit()
        elif opt in ("-r"):
            determinist = False
        elif opt in ("-d"):
            determinist = True
        elif opt in ("-o"):
            offset = int(arg)
            assert 0 <= offset < 32
        elif opt in ("-e"):
            errval = int(arg)
            assert 0 <= errval < 256

    ## We can simulate the attack using the signwithfault function:
    if determinist:
        sk = unhexlify('523b05d3a02887f67eef8bec3f723dc2c1773200d779fa8d1f5f2afbd84ef529')
        message = b'test'
    else:
        sk = os.urandom(seedlen)
        message = os.urandom(seedlen)
        offset = random.randrange(0,32)
        errval = random.randrange(1,256)
    
    print('Key generation:')
    pk = publickey(sk)
    a = bytes_to_clamped_scalar(H(sk)[:32]) % l
    print('a = ' + str(a))
    sign = signature(message, sk, pk)
    print('First signature is valid : ' + str(checkvalid(sign, message, pk)))
    
    sign2 = signwithfault(message,sk,pk, offset, errval)
    
    print('Second signature is valid: ' + str(checkvalid(sign2, message, pk)))
    print('Same R but not the same S: ' + str((sign[:32]==sign2[:32]) and (sign[32:]!=sign2[32:])))
    
    # Recover the secret key:
    offset, recovereda = recovera(sign, sign2, pk, message)
    assert recovereda == a, "Attack not successful"
    print('Found a with error at offset %d' % offset)
    print('a = ' + str(recovereda))
    
    # # We can sign another message using a random r value
    print('Signing another message:')
    texttosign = b'anothermessage'
    
    newsign = signwitha(texttosign, pk, recovereda)
    print('Third signature is valid: ' + str(checkvalid(newsign, texttosign, pk)))
