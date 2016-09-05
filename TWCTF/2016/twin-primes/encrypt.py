from Crypto.Util.number import *
import Crypto.PublicKey.RSA as RSA
import os

N = 1024

def getTwinPrime(N):
    while True:
        p = getPrime(N)
        if isPrime(p+2):
            return p

def genkey(N = 1024):
    p = getTwinPrime(N)
    q = getTwinPrime(N)
    n1 = p*q
    n2 = (p+2)*(q+2)
    e = long(65537)
    d1 = inverse(e, (p-1)*(q-1))
    d2 = inverse(e, (p+1)*(q+1))
    key1 = RSA.construct((n1, e, d1))
    key2 = RSA.construct((n2, e, d2))
    if n1 < n2:
        return (key1, key2)
    else:
        return (key2, key1)

rsa1, rsa2 = genkey(N)

with open("flag", "r") as f:
    flag = f.read()
padded_flag = flag + "\0" + os.urandom(N/8 - 1 - len(flag))

c = bytes_to_long(padded_flag)
c = rsa1.encrypt(c, 0)[0]
c = rsa2.encrypt(c, 0)[0]

with open("key1", "w") as f:
    f.write("%d\n" % rsa1.n)
    f.write("%d\n" % rsa1.e)
with open("key2", "w") as f:
    f.write("%d\n" % rsa2.n)
    f.write("%d\n" % rsa2.e)

with open("encrypted", "w") as f:
    f.write("%d\n" % c)
