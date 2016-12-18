# TPQ (150 p)

```
$ nc ctf.sharif.edu 4000

Our ultra-secure system is generating 10 primes... Done!
Please choose options quickly and carefully.
Options:
	[C]hoose two distinct indices to encrypt the flag
	[R]eveal the encryption function
	[Q]uit.
R
def encrypt(m, p, q):
	e = 65537
	return gmpy2.powmod(bytes_to_long(m), e, p*q)
COptions:
	[C]hoose two distinct indices to encrypt the flag
	[R]eveal the encryption function
	[Q]uit.

Send two distinct indices smaller than 10, separated by space.
1 2
The encrypted flag is: 17861572053284394125176760836703743079629678987239186015528231223232675465946931400502427395119650612013595034873034198155429807732685251361597545457876908985526444125415216420573782838555000744604172761327568798131061901911266845790464690269260499671470623274974912621307770161610558160052600363987405838736
```

At the start of a session, the server generates 10 primes (p₁, ... p₁₀). We obtain RSA ciphertexts encrypted with moduli N = pᵢpⱼ for indices i and j, i.e., mᵉ = cᵢⱼ (mod pᵢpⱼ), or equivalently, mᵉ = cᵢⱼ + kᵢⱼpᵢpⱼ for some integer kᵢⱼ. Setting up a set of equations of the form

mᵉ = c₁ⱼ + k₁ⱼp₁pⱼ
mᵉ = c₁ᵢ + k₁ᵢp₁pᵢ
...
mᵉ = c₁ᵤ + k₁ᵤp₁pᵤ

we get

c₁ⱼ + k₁ⱼp₁pⱼ - c₁ᵢ - k₁ᵢp₁pᵢ = 0 ⟺ c₁ⱼ - c₁ᵢ =  p₁m
...
c₁ⱼ + k₁ⱼp₁pⱼ - c₁ᵤ - k₁ᵤp₁pᵤ = 0 ⟺ c₁ⱼ - c₁ᵤ =  p₁n

so computing the GCD's of each such difference, we obtain a multiple of p₁. Repeating this, with the intention of filtering out addtional common factors, we obtain the first prime factor of the encrypted ciphertext modulus. We do the same thing for the other factor as well:

```python
from fractions import gcd
import libnum
from pwn import *

def get_ciphertext(i,j):
    print '[+] Querying {0}, {1}'.format(i,j)
    r.recvuntil('[Q]uit.')
    r.send('C')
    r.recvuntil('.')
    r.send(str(i) + ' ' + str(j))
    r.recvline()
    return int(r.recvline().split(':')[1])

r = remote('ctf.sharif.edu', 4000)

a = get_ciphertext(1,2)
b = get_ciphertext(1,3)
c = get_ciphertext(1,4)
d = get_ciphertext(1,5)

p = abs(gcd(gcd(a-b,a-c),gcd(a-b,a-d)))

b = get_ciphertext(2,3)
c = get_ciphertext(2,4)
d = get_ciphertext(2,5)

q = abs(gcd(gcd(a-b,a-c),gcd(a-b,a-d)))

d = libnum.modular.invmod(65537, (p-1)*(q-1))

print libnum.n2s(pow(a, d, p*q))
```

which prints

```
SharifCTF{7c62f12e7e6f08f9f5365e45588d34d8}
```

# Unterscheide (200 p)

We have a code

```python
#!/usr/bin/python

import gmpy
import random, os
from Crypto.Util.number import *
from Crypto.Cipher import AES


from secret import flag, q, p1, p2, h

assert (gmpy.is_prime(q) == 0) + (q-1) % p1 + (q-1) % p2 + (p2 - p1 > 10**8) + (pow(h, 1023*p1*p2, q) == 1) == 0

key = os.urandom(128)
IV = key[16:32]
mode = AES.MODE_CBC
aes = AES.new(key[:16], mode, IV=IV)
flag_enc = aes.encrypt(flag)

rand = bytes_to_long(key)
benc = bin(bytes_to_long(flag_enc))[2:]

A = []
for b in benc:
	try:
		r = gmpy.next_prime(random.randint(3, q-2))
		s = gmpy.invert(r, q-1)
		if b == '0':
			a = pow(h, r*r*p1, q)*q*rand + rand + 1
		else:
			a = pow(h, s*s*p2, q)*q*rand + rand + 1
		A.append(str(int(a)))
		rand += 1
	except:
		print 'Failed :|'
	
fenc = open('enc2.txt', 'w')
fenc.write('\n'.join(A))
fenc.close()
```

The first thing we determine is q. We can do this by computing the difference between ciphertexts, since then the part rand + 1 will cancel out, leaving something which is a multiple of q (and not rand, since it it differs by 1). Doing the same things as in the previous challenge, we can filter out additional factors.


```python
f = open('enc.txt', 'r')
pos = 0
for line in f:
    numbers.append(int(line)-pos)
    pos += 1
    
for n in range(0, len(numbers)-1, 3):
    u = gcd(numbers[n+1] - numbers[n], numbers[n+2] - numbers[n])
    if gmpy.is_prime(u):
        print u
```

This gives that

```python
q = 165269599219445291398173635845501465893177201997714520052835716101366991703599089397287042721096067409772119897046741565500293370740283586460353393394630534349929558358109284225649030217655081372910120058487153005673592680613247698577655983823064226042058852387960865050147174483989378148446338590249438249083
```

From the assertion in the code, we assume that p₁ and p₂ are pretty close, differing by about ~ 10⁸. A simple brute force can be done as follows:

```python
m = gmpy.root((q-1)/2, 2)[0]

for i in range(0, 2**25):
    if (q-1) % m == 0:
        print m
    m += 1
```

We find that

```python
p1 = 9090368507916642523150386537322321669636426087368916042946887058939035329547274618743911402935105936038626517888669029591219526735351668782037241444579211 
p2 = (q-1)/p1/2
```

Knowing q, we can now also find rand (key), as an encrypted ciphertext c mod q = rand + 1:

```python
key = 27520790357638948793357070133680303498308234098213169355930451551473551610668598275338166450612066732646304998053583305691477103900019807357983049075051458007108229556072342519889701952853559033481920882888665392738949159879012748283810392571373411251358969454208761074291792134766062048754841099848058011309
```

Finally, we get the ciphertext as

```python
f = open('enc.txt', 'r')
for line in f:
    numbers.append((int(line)-key-1) // key // q)
    key += 1
	
binrep = ''
for u in numbers:
    if pow(u,  2*p2, q) == 1:
        binrep += '1'
    else:
        binrep += '0'
enc = int(binrep,2)

enc = (libnum.n2s(enc))
key = (libnum.n2s(key))

IV = key[16:32]
mode = AES.MODE_CBC
aes = AES.new(key[:16], mode, IV=IV)
print aes.decrypt(enc)
```

which prints

```
'** SharifCTF{10ED2D76BCC417D9C48BE67F6790AF70}**'
```