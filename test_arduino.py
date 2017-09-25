#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from eddsafault import checkvalid, recovera
from binascii import unhexlify

# Faulted signatures from Ardiono Nano board
faultedSignatures = [
    unhexlify('d49bd03b98b85afbcff46bfacf9af673662a253871ec9a56d035aefad2166e5449f230f6967071855663997a5fe0562f73caec8cceaa202a8ba39c1cee807c0b'),
    unhexlify('d49bd03b98b85afbcff46bfacf9af673662a253871ec9a56d035aefad2166e54b2811f21f6e1f7d92d393621bc0584ee7b289a357448ec54bd3d7f21d42aee0f'),
    unhexlify('d49bd03b98b85afbcff46bfacf9af673662a253871ec9a56d035aefad2166e5467a7f6fc4a0270d5b2e238777b4453cd9733e4f4052b5b097c21fc3062b8b008'),
    unhexlify('d49bd03b98b85afbcff46bfacf9af673662a253871ec9a56d035aefad2166e5458b12c240028c2e854a1f373b874732e655b1780fca01001fe12691b93879500'),
    unhexlify('d49bd03b98b85afbcff46bfacf9af673662a253871ec9a56d035aefad2166e544b4934ee480c076ab4b19ed375044f4e601ccb7a751b4b81cf8c607d9122e00b')]

if __name__ == "__main__":
    print('Fault from Arduino Nano voltage glitch:')
    # Arduino public key:
    pubKey = unhexlify('9c74125c9a2bcfbc6107bcdb00b79b938112b3ec2fa4db67b7128f2a8cc9da43')
    signedtext = b'test1' + b"\x00"*27
    sign1 = unhexlify('d49bd03b98b85afbcff46bfacf9af673662a253871ec9a56d035aefad2166e54')# the R value
    sign1 += unhexlify('1642b09174b00e34f617f1f758e2b0f71713da45f99f729a3175a4f77f475f08')# the S value
    print("signature 1 is valid: " + str(checkvalid(sign1, signedtext,  pubKey)))
    
    for s in faultedSignatures:
        # We can verify that the 1st signature is valid and which is not:
        print("signature 2 is valid: " +  str(checkvalid( s, signedtext, pubKey)))
        # And we crack it, firstly the valid signature and then the invalid signature:
        offset, recovereda = recovera(sign1, s, pubKey, signedtext)
        if offset != None:
            print('Found value of a thanks to error at offset %d' % offset)
            print('a = ' + str(recovereda))
