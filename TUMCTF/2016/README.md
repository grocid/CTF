# Haggis (100p)

The task is to compute a ciphertext which encrypts to a ciphertext with a given randomly generated 16-byte string. Let us look at AES-CBC:

``` 
     IV     K
     |      |
     |      V
     V   +-----+
P₀ ->⊕-> |  C  | --+-->
         +-----+   |
     +-------------+
     |             
     V   +-----+
P₁ ->⊕-> |  C  | --> ...
         +-----+   

```

The basic idea is: we can invert the last step and choose a proper P₁ such that we get the desired last block (target). The previous ciphertext block is given, so we may compute

x = C(P₀ ⊕ IV)
y = C⁻¹(target, k)

so, we set

P₁ = x ⊕ y = C(P₀ ⊕ IV, k) ⊕ C⁻¹(target, k)

There is a little bit of hassle with the padding. Since we cannot choose the last byte of P₁, we have to query the server for target blocks until P₁ becomes 0x01. Since this occurs with probability 1/256, we do not have to wait too long :-)

The following code solves the problem:

```python
import os, binascii, struct
from Crypto.Cipher import AES
from pwn import *
context.log_level = 'error'

def pad(m): 
    return m + b'\x01'

# adjusted padding
def ppad(m):
    prefix = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + chr(len(m) + 16 - 1)
    return bytes(prefix + data)

def opad(m):
    data = pad(m)
    prefix = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + chr(len(data) - 1)
    return bytes(prefix + data)

def pr(x):
    return binascii.hexlify(x).decode()

while True:
    # connect to server
    s = remote('104.198.243.170', 2501)
    
    # a pre-padded message
    data = b'I solemnly swear that I am up to no good.\0I do!!'

    # receive challenge
    challenge = s.recvuntil('\n').strip('\n')
    print '[+] Got challenge {0}'.format(challenge)
    
    # some data
    target = binascii.unhexlify(challenge)
    pub = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # setup ciphers
    crypt0r = AES.new(pub, AES.MODE_CBC, pub)
    decrypt0r = AES.new(pub, AES.MODE_ECB, pub)

    # compute our padding block
    extrablock = ''.join(chr(ord(x)^ord(y)) for x, y in 
                    zip(crypt0r.encrypt(ppad(data))[-16:], 
                    decrypt0r.decrypt(target)))

    crypt0r = AES.new(pub, AES.MODE_CBC, pub)
    payload = data + extrablock
    
    if payload[-1] == '\x01':
        s.send(pr(payload[:-1]) + '\n')
        print s.recvuntil('\n')
        break
    s.close()
```

Running it gives the flag

```
hxp{PLz_us3_7h3_Ri9h7_PRiM1TiV3z}
```


# Tacos partial (400 p)

Upon request, the server takes two numbers p and q. It checks that both p and q are primes, that p divides (q-1) and that 2¹⁰²⁴ < p < q < 2⁴⁰⁹⁶. Now, this may pose a tiny problem for us since q-1 will have a large prime factor p and therefore we cannot use Pohlig-Hellman efficiently - its complexity will be of order O(√p) or ~ √2¹⁰²⁴.

Oh, my. This challenge was pretty hard. I spent several hours pondering, occasionally feeling a bit stupid. But then, finally, it hit me. There is absolutely no way to use the Pohlig-Hellman algorithm successfully if p is a real prime. So, can we cheat?

Now, I turned my attention to the primality test function, which I previously had neglected. What if we can create a composite (and B-smooth number) that actually is reported as a prime? It is a Fermat primality test... and there is an infinite set of composite numbers such that for any such number n it holds that aⁿ⁻¹ = 1 mod n. This set is called the Carmichael numbers.

Turns out finding such a large Carmichael number is in itself a quite hard problem, since the set is incredible sparse. Erdos proposed a method, but it is time consuming as hell. After a bit of Googling, I found that Daniel Bleichenbacher have had about the same idea and already had pre-computed a 1095 bit Carmichael number. Great!

We may set

   p = 398462957079251 · 28278016308851 · 268974870654491 · 1239515532971 · 
   	   12941222544251 · 2825874899 · 182200861571 · 480965007251 · 
	   8028415890251 · 761874633627251 · 10326412038251 · 105324823451 · 
	   7128348371 · 29542620251 · 251906132167691 · 64654312451 · 226698699371 · 
	   130685132579 · 9167201891 · 432876391197251 · 3077983389251 · 17767646051 · 
	   9371850251 · 954045342251 ·  112810627931 · 6297653304192251 · 20842025454251

OK, so the Fermat primality test accepts both p and q = 2 · p + 1 as primes! Very nice! Now, with running Pohlig-Hellman with q, we get a nice and smooth q - 1. I fired up Sage and started running my own P-H function with the parameters received from the server, all excited.

After a minute or so, I sensed some disappointment. It is not running fast enough. The server will accept no queries after 60 seconds passed and my algorithm was already above that time limit. Seemingly, the factors of p were too large (in conjunction with a large modulus), taking about 60 seconds each to process in the P-H function. Due to the problem of finding a more suitable Carmichael number, I could not proceed any further.

The intention was good, but the circumstances made it impossible. Still, I think it was worth sharing.