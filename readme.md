# Fault attack on EdDSA and Ed25519
We demonstrated how to recover enough part of the secret key of a device performing EdDSA signatures thanks to a single fault at the right time to be able to produce seemingly valid signature (even though the real signature by the actual secret key holder would not have the same value). This is an inherent weakness of the algorithms and cannot be avoided as long as the algorithms are generating their values through deterministic means. Our paper was presented during [FDTC 2017](www.fdtc-workshop.eu). We give here the code to perform fault signature simulations as well as key recovery from faulted signatures.

In our example setup, we were able to attack and recover the secret key stored in an Arduino Nano running Ed25519 signature using the [ArduinoLibs](https://rweather.github.io/arduinolibs/crypto.html).

Countermeasures against such fault attacks are detailled in our paper "Practical fault attack against the Ed25519 and EdDSA signature schemes".


## Requirements

* Python 2.6+
* gmpy2

## Attack simulation
The Python script **test_simulation.py** simulates a fault happening during the signature process and applies the attack to recover the private value `a`:

```bash
./test_simulation.py -r
Key generation:
a = 3856099267433939410638934773561861774469861534617912158986655171120805876879
First signature is valid : True
Second signature is valid: False
Same R but not the same S: True
Found a with error at offset 31
a = 3856099267433939410638934773561861774469861534617912158986655171120805876879
Signing another message:
Third signature is valid: True
```

By default keys, fault offsets and values are randomly generated. However, deterministic tests may be run:
```bash
$ ./test_simulation.py -d -o 12 -e 56
Key generation:
a = 482006232232683921242586128535238829962455780187631138037190845242801001519
First signature is valid : True
Second signature is valid: False
Same R but not the same S: True
Found a with error at offset 12
a = 482006232232683921242586128535238829962455780187631138037190845242801001519
Signing another message:
Third signature is valid: True
```

## Arduino attack
To perform the attack on Arduino Nano, Arduino Studio must be installed and the Crypto library of the ArduinoLibs project have to be imported. The code executed on Arduino Nano is given in the file **ed25519.ino**. The complete set-up and methodology to obtain faults by voltage glitch are given in the paper.

Once the proper faults have been found, the script **test_arduino.py** recovers the value `a` from the faulted signatures:

```bash
$ ./test_arduino.py 
Fault from Arduino Nano voltage glitch:
signature 1 is valid: True
signature 2 is valid: False
Found value of a thanks to error at offset 6
a = 5261030905596737613781015704137862010759183555703583748072526152929652983426
signature 2 is valid: False
Found value of a thanks to error at offset 4
a = 5261030905596737613781015704137862010759183555703583748072526152929652983426
signature 2 is valid: False
Found value of a thanks to error at offset 2
a = 5261030905596737613781015704137862010759183555703583748072526152929652983426
signature 2 is valid: False
Found value of a thanks to error at offset 1
a = 5261030905596737613781015704137862010759183555703583748072526152929652983426
signature 2 is valid: False
Error
Error: the glitch was not at offset 32
```

## Publication  
Article's DOI: [10.1109/FDTC.2017.12](https://doi.org/10.1109/FDTC.2017.12)  
The accepted version is [freely available](https://romailler.ch/ddl/10.1109_FDTC.2017.12_eddsa.pdf).

## Copyrights
Our original source code is copyright © 2017 Nagravision S.A., and was written by Sylvain Pelissier and Yolan Romailler.

The Ed25519 python implementation is based on DJB's work, the Ed25519 software is in the public domain.

The software published here is in under the Unlicense. 
