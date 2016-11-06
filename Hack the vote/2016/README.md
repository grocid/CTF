# TOPKEK (50 p)

```
A CNN reporter had only one question that she couldn't get off her mind

Do we even know, who is this 4 CHAN???

So she set out to find who this 400lb hacker is. During her investigation, 
she came across this cryptic message on some politically incorrect forum online, 
can you figure out what it means?
```

There is a ciphertext attached to this challenge, which contains the following:

```
KEK! TOP!! KEK!! TOP!! KEK!! TOP!! KEK! TOP!! KEK!!! TOP!! KEK!!!! TOP! KEK! TOP!! KEK!! TOP!!! KEK! TOP!!!! KEK! TOP!! KEK! TOP! KEK! TOP! KEK! TOP! KEK!!!! TOP!! KEK!!!!! TOP!! KEK! TOP!!!! KEK!! TOP!! KEK!!!!! TOP!! KEK! TOP!!!! KEK!! TOP!! KEK!!!!! TOP!! KEK! TOP!!!! KEK!! TOP!! KEK!!!!! TOP!! KEK! TOP!!!! KEK!! TOP!! KEK!!!!! TOP! KEK! TOP! KEK!!!!! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK!! TOP!! KEK!!! TOP! KEK! TOP!! KEK! TOP!! KEK! TOP! KEK! TOP! KEK! TOP!!!!! KEK! TOP!! KEK! TOP! KEK!!!!! TOP!! KEK! TOP! KEK!!! TOP! KEK! TOP! KEK! TOP!! KEK!!! TOP!! KEK!!! TOP! KEK! TOP!! KEK! TOP!!! KEK!! TOP! KEK!!! TOP!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK!!! TOP!! KEK!! TOP!!! KEK! TOP! KEK! TOP! KEK! TOP! KEK!! TOP!!! KEK!! TOP! KEK! TOP!!!!! KEK! TOP!!! KEK!! TOP! KEK!!! TOP!! KEK!!! TOP! KEK! TOP!! KEK!! TOP!!! KEK! TOP! KEK!! TOP! KEK!!!! TOP!!! KEK! TOP! KEK!!! TOP! KEK! TOP!!!!! KEK! TOP!! KEK! TOP!!! KEK!!! TOP!! KEK!!!!! TOP! KEK! TOP! KEK! TOP!!! KEK! TOP! KEK! TOP!!!!! KEK!! TOP!! KEK! TOP! KEK!!! TOP! KEK! TOP! KEK!! TOP! KEK!!! TOP!! KEK!! TOP!! KEK! TOP! KEK! TOP!!!!! KEK! TOP!!!! KEK!! TOP! KEK!! TOP!! KEK!!!!! TOP!!! KEK! TOP! KEK! TOP! KEK! TOP! KEK! TOP!!!!! KEK! TOP!! KEK! TOP! KEK!!!!! TOP!! KEK! TOP! KEK!!! TOP!!! KEK! TOP!! KEK!!! TOP!! KEK!!! TOP! KEK! TOP!! KEK! TOP!!! KEK!! TOP!! KEK!! TOP!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP!! KEK!! TOP!! KEK!! TOP!!! KEK! TOP! KEK! TOP! KEK! TOP!! KEK! TOP!!! KEK!! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK! TOP!!!!! KEK! TOP! KEK!! TOP! KEK! TOP!! KEK!! TOP!! KEK!! TOP!! KEK! TOP! KEK!! TOP! KEK! TOP!! KEK!! TOP! KEK!!!! TOP! KEK!! TOP! KEK!!!! TOP! KEK!! TOP! KEK!!!! TOP! KEK! TOP!!!!! KEK! TOP!
```

First guess is a binary, and judging from the amount of points given for this challenge, that is probably no more complicated than that. `TOP` is either `0` or `1` and the number of `!` denotes the number of each symbol. We try both and find that `TOP` maps to `1`, so `KEK` is `0`. The following code decodes the ciphertext.

```python
split_cipher = ciphertext.split()
decrypted = ''
for block in split_cipher:
    if block.startswith('KEK'):
        decrypted += '0' * (len(block) - 3)
    else:
        decrypted += '1' * (len(block) - 3)

decrypted = int(decrypted, 2)
print libnum.n2s(decrypted)
```

This gives

```
flag{T0o0o0o0o0P______1m_h4V1nG_FuN_r1gHt_n0W_4R3_y0u_h4v1ng_fun______K3K!!!}
```
# Trump Trump (100 p)

```
With Trump about to be in office, autographed photos of him are selling like wildfire. The only problem is:
Trump makes it a point to never sign a photo of himself. If you could get a signed picture, you could 
stand to make DOZENS of dollars.

nc trumptrump.pwn.republican 3609
```

We get the following parameters

```python
e = 65537
N = 23377710160585068929761618506991996226542827370307182169629858568023543788780175313008507293451307895240053109844393208095341963888750810795999334637219913785780317641204067199776554612826093939173529500677723999107174626333341127815073405082534438012567142969114708624398382362018792541727467478404573610869661887188854467262618007499261337953423761782551432338613283104868149867800953840280656722019640237553189669977426208944252707288724850642450845754249981895191279748269118285047312864220756292406661460782844868432184013840652299561380626402855579897282032613371294445650368096906572685254142278651577097577263
```
Converting the image to a number

```python
f = open('trump.jpg', 'r')
data = libnum.s2n(f.read()) % N
```

we try to submit it, which incidentially fails. We can exploit that sign(a) × sign(b) = sign(a × b). Since the image is divisible by for instance 5, we can factor out this and sign the two parts separately.

```
sign(data / 5) = 15742105247958736958004859844860106392650529642491444791655288653059139800053206167023792876159338330811553994563264038797209523053486931817881299156223450837206775783069574776254654197337314541494064874054449749920216258529257414289049794126137529358458843274774718683434637726891822317083908587215429977340799931758155377373656742947190372216055450421108566287038161365843817023142180328035768992726841684537565155117632165969899505426984495819465218509929865350057283134017766501372618581237936784285588661088765130624093014320161531747074858737002260566015050922492437422682387506583350890218827504186050632600504
sign(5) = 18938431620064949405099081881389422411569506620645684785718437650149907701313939238017399264771270907473551575023831816899182480214946633959498312433619616816861526269114681215528914329791099013891595131862543300865871379621247867883669403120593815746911158013483346808195756730946735362037791985948842449343328484149265803462983935765047801620079220588638013959948297979415581591179722303271496129424130559547762467547913292325129340535450673107267746074776721093375970510983576513946461957148135755448610570645462794635156136176208419134557678284424568016798221633694322809374691561612990098051154456165773266086828
```
so,

```
sign(data) = 7240527260044126899075832339973255923943354335060037001558105343295495841635843603507411996488568977206115374657942401805673165802944813082589201103827861325639581582005106924492724100812077464571265915352012064311221086996199961637876724784326540728342282620427706011099830010859187486529928704673604893811823836195858916605646466850177580221970723526928598144155086898666864544017092301766812496415256830844105167571316067435310083881243302996555421199570092966497927454347195963984192282682803663188954259681974561132158520131591167970511602803401392202553720288822909116428852233039667283953852194960467196349739
```

Sending this to the service, we get

```
Duneld Trump: Well, I already met my quota for Guantanimo Bay inmates today, so okay.
Trump looks shocked, appalled by the fact that he'd sign a picture of himself for such a not-billionaire.
Trump sprints away at a blinding 2mph, dropping what he was carrying.
It's a stack of photos, you pick one up and look at it.
ffd8ffe000104a46494600010101006000600000ffdb0043000302020302020303030304030304050805050404050a070706080c0a0c0c0b0a0b0b0d0e12100d0e110e0b0b1016101113141515150c0f171816141812141514ffdb00430103040405040509050509140d0b0d1414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414ffc20011080173029403011100021101031101ffc4001d000002020301010100000000000000000003040102000506070809ffc4001b01000301010101010000000000000000000002030104050607ffda000c03010002100310000001f9904c0c090837024303025896590c36431480cc202776420c90c0c08090c090c090c3242c6f5136f41853dd38e9d0ab557756b58562b284099bb4657767675d55339066f27e8978ef673ebc3030dc08090c330303021770302ccb3b9218658622e955ec8d20...
```

Let us write code to make it viewable:

```python
import libnum
from pwn import *

v = remote('trumptrump.pwn.republican', 3609)
v.recv(1024)
v.send(str(s) + '\r\n')

for i in range(4): v.recvline()
data = v.recvline()
open('trump1.jpg','w').write(libnum.n2s(int(data, 16)))
```

![flag](trump1.jpg)


# Vermatrix Supreme (100 p)

```
Working in IT for a campaign is rough; especially when your candidate uses his password as the IV for your 
campaign's proprietary encryption scheme, then subsequently forgets it. See if you can get it back for him.
The only hard part is, he changes it whenever he feels like it.

nc vermatrix.pwn.democrat 4201
```

Along this, we get the code for the encryption scheme.

```python
import sys, random, time

flag = "flag{1_sw34r_1F_p30Pl3_4cTu4lLy_TrY_Th1s}"

def printmat(matrix):
	for row in matrix:
		for value in row:
			print value,
		print ""
	print ""

def pad(s):
	if len(s)%9 == 0:
		return s
	for i in xrange((9-(len(s)%9))):
		s.append(0)
	return s

def genBlockMatrix(s):
	outm = [[[7 for x in xrange(3)] for x in xrange(3)] for x in xrange(len(s)/9)]
	for matnum in xrange(0,len(s)/9):
		for y in xrange(0,3):
			for x in xrange(0,3):
				outm[matnum][y][x] = s[(matnum*9)+x+(y*3)]
	return outm


def fixmatrix(matrixa, matrixb):
	out = [[0 for x in xrange(3)] for x in xrange(3)]	
	for rn in xrange(3):
		for cn in xrange(3):
			out[cn][rn] = (int(matrixa[rn][cn])|int(matrixb[cn][rn]))&~(int(matrixa[rn][cn])&int(matrixb[cn][rn]))
	return out


def chall():
	IV = [c for c in '?????????']
	seed = "??????????????????"

	blocks = genBlockMatrix(pad(IV + [ord(c) for c in seed]))

	res = [[0 for i in xrange(3)] for i in xrange(3)]
	for i in xrange(len(blocks)):
		res = fixmatrix(res, blocks[i])


	print "SEED: " + str(seed)
	printmat(res)

	data = raw_input("")

	data = data.replace(' ', '').strip().split(',')

	if len(data) != 9:
		return False

	for i in xrange(len(IV)):
		if str(IV[i]) != str(data[i]):
			return False

	return True

if chall():
	print flag
```

The `IV` is a series of 9 numbers in some undefined range. Instead of spending a bunch of time to find some algebraic relations that we can exploit, we can use Z3. We define a set of variables (BitVec) for Z3, representing the unknown `IV`.  Since the matrix we receive should contain the same values as the computed one, given `seed` and the correct `IV`, we set up equality relations.

```python
from z3 import *
from pwn import *
from vermatrix import *

def find_iv(seed, target):
    s = Solver()
    IV = [BitVec('%d' % i, 32) for i in range(1,10)] 
      
    blocks = genBlockMatrix(pad(IV + [ord(c) for c in seed]))
    res = [[0 for i in xrange(3)] for i in xrange(3)]
    
    for i in xrange(len(blocks)):
        res = fixmatrix(res, blocks[i])

    for y1, y2 in zip(res, target): 
        for x1, x2 in zip(y1, y2): 
            s.add(x1 == x2) # they should be equal!
    
    return s
```

Now, we can use this routine in connecting to the server as follows:

```python
context.log_level = 'error'
v = remote('vermatrix.pwn.democrat', 4201)

seed = v.recvline().split()[1]
target_matrix = [[int(x) for x in v.recvline().split()] for i in range(0, 3)]
s = find_iv(seed, target_matrix)

if s.check() == sat:
    m = s.model()
    out = [0]*9
    for x in m:
        out[int(str(x))-1] = m[x]
    v.send(str(out)[1:-1] + '\n')
    print 'FLAG: {0}'.format(v.recvline())
```

Running the whole code, we obtain

```
flag{IV_wh4t_y0u_DiD_Th3r3}
```

# Boxes of Ballots (200 p)

```
Privjet Komrade!

While doing observing of Amerikanski's voting infrascture we find interesting box. 
We send operative to investigate. He return with partial input like showing below.
He say box very buggy but return encrypted data sometimes. Figure out what box is
do; maybe we finding embarass material to include in next week bitcoin auction, yes?

ebug": true, "data": "BBBBBBBBBBBBBBBB", "op": "enc"}

nc boxesofballots.pwn.republican 9001
```

This challenge is very similar to [this](https://github.com/grocid/CTF/tree/master/IceCTF/2016#l33tcrypt-90-p)). We can solve it as follows:

```python
from pwn import *
import json
import string

def getdata(res):
    for l in res.split('\n'):
        if l.startswith('{"Status"'):
            return json.loads(l)['data']

def getreference(buflen, v):
    data = {"debug": False, "data": 'x'*buflen , "op": "enc"}
    payload = json.dumps(data).replace('False', 'false')
    v.send(payload + '\n')
    response = v.recv(1024)
    ref = getdata(response)[:64]
    return ref

context.log_level = 'error'
v = remote('boxesofballots.pwn.republican', 9001)
result = ""
buflen = 31

while buflen:
    ref = getreference(buflen, v)

    for i in string.printable:
        data = {"debug": False, "data": 'x'*buflen + result + i, "op": "enc"}
        payload = json.dumps(data).replace('False', 'false')

        v.send(payload + '\n')
        response = v.recv(1024)
        res = getdata(response)
        if res[:64] == ref:
            result += i
            buflen -= 1
            print result
            break
    else:
        print "[-] Error"
        exit(-1)
```

gives

```
flag{Source_iz_4_noobs}
```

Michał Żuberek ([Z](http://z.bigi.pl)) of my team Snatch the Root solved this one.

# The Best RSA (250 p)

```
At his last rally, Trump made an interesting statement:

I know RSA, I have the best RSA
The more bits I have, the more secure my cyber, and my modulus is YUUUUUUUUUUUUUGE
We don't believe his cyber is as secure as he says it is. See if you can break it for us
```

We get a file with a public exponent `e = 65537` and a massive public modulus `N`. Clearly, there is something strange with this modulus. The first obvious move is to check for small factors, and in fact, we find that 3 is a factor. Not once, but several times. The whole modulus consist of very small prime factors. Let us write some code to factor it!

```python
import libnum, grocid, challenge

def get_private_exponent(phi, e):
    return libnum.modular.invmod(e, phi)

def find_factors(n, h):
    primes = grocid.sieve(h)
    factors = {}
    for p in primes:
        while n % p == 0:
            n = n / p
            if p in factors:
                factors[p] +=1
            else:
                factors[p] = 1
    return factors

print '[+] Factoring n...'
single_factors = find_factors(challenge.n, 10000)
```

OK, so we got a dictionary containing each prime factor and its corresponding exponent. It looks like this:

```python
{3: 1545, 5: 1650, 7: 1581, 137: 1547, 11: 1588, 13: 1595, 17: 1596, 19: 1553, 149: 1572, 23: 1579, 29: 1549, 31: 1613, 163: 1589, 37: 1594, 167: 1578, 41: 1524, 43: 1538, 173: 1617, 47: 1571, 229: 1610, 179: 1556, 53: 1635, 59: 1556, 151: 1549, 61: 1605, 181: 1582, 193: 1549, 67: 1606, 197: 1520, 71: 1589, 73: 1571, 241: 1564, 79: 1548, 83: 1630, 139: 1638, 89: 1535, 199: 1574, 223: 1610, 97: 1456, 227: 1600, 131: 1540, 101: 1514, 103: 1583, 233: 1564, 107: 1591, 109: 1529, 239: 1556, 157: 1600, 113: 1601, 211: 1544, 251: 1493, 191: 1564, 127: 1565}
```

So, we can compute ϕ and the corresponding private exponent:

```python
phi = challenge.n
print '[+] Computing phi...'
for p in single_factors:
    phi = phi / p * (p - 1)

print '[+] Computing private exponent'
d = get_private_exponent(phi, 65537)
```

This enables us to decrypt! However, if you try it, you will probably notice that it takes quite some time and memory to compute cᵈ (mod n). Now, we can speed this a bit using CRT. So, we compute cᵈ (mod 3¹⁵⁴⁵) and so on separately, for each prime factor and then use CRT to reconstruct the whole message:

```python
remainders = []
moduli = []

for p in single_factors:
    modulus = pow(p, single_factors[p])
    moduli.append(modulus)
    remainder = pow(challenge.c, d, modulus)
    remainders.append(remainder)

plaintext = libnum.modular.solve_crt(remainders, moduli)
print 'Message: {0}'.format(libnum.n2s(plaintext))
```

It still takes some time to complete, but it is managable (left it running while doing other stuff so...). It could possibly be made faster by Hensel lifting, but I decided not to try it. When done, we get a message which is a image file.:

![Decrypted](decrypted.gif)

# Baby's hands (300 p)
```
We think that Trump's right hand man has been sending out flags from his personal 
computer, but we need to be sure. See if you can make anything out of the traffic
we intercepted.
```

The initial two lines are

```python
{d:n:c}
{64193765095472280945778947695026260940793161700792092928929371930940586875921621250436677664062645637750266086941620369817913432656342447118119648040487568561166129534408858429501807430550886328164336961068507005046531729954378900389289038547121166749974617776234380115780563231906876010653549490718147637109:162375468556255342840184380017752307049575955143811124651668179546999144455415632265862602514386409412258772643790637233144774447636694664087397175482938958661142022166864007317692608104513835959387316735889741416403005613839667775733147723497537341613995375357897642024075069112712472560335406551536669543677:161368580245997137625438248139098888389801359838792140099794084052829279383422322670122662786704858201672541232233171127388341066584896672407182421832728901923771676356720611937864219195771372253188974650818854505110963737925290199983571032857746780899310446337006151661497839040062867489758146326490061720009}
```

OK, so the private exponent `d` is published. We try to compute cᵈ (mod n) and look at the binary data with binwalk. No results. Hm... so, what if we need the public exponent `e` to compute the plaintext? We can probably find this with Wieners attack! Let us try it!

```python
import libnum, grocid

f = open('intercepted', 'r')

data = f.read()
data = data.split('\n')

for line in data[1:]:
    d, n, c = [int(x) for x in line[1:-1].split(':')]
    e = grocid.wiener.attack(d, n)
```

This yields

```
flag{G3t_1t?_1t_h4s_4_sm4ll_d}
```


# SMTPresident (400 p)

```
The FBI reopened their investigation of Hillary Clinton after they 
recovered some interesting files from her personal email server.

emails
pubkeys
flag
```

The file `pubkeys` contains a set of public keys with very small public exponent (e = 17). Assuming that every message sent on the same date is identical, we can use Håstad's broadcast attack. Incidentially, we have 17 of each every date. The following Python code will do just fine:


```python
from os import listdir
from os.path import isfile, join
from Crypto.PublicKey import RSA
from base64 import b64decode
import re, libnum, gmpy

def get_files(path):
     return [f for f in listdir(path) if isfile(join(path, f))]
     
pubkeysfiles = get_files('./pubkeys')
emailfiles = get_files('./emails')
pubkeys = {}
encrypted_emails = {}

for pubkeyfile in pubkeysfiles:
    f = open('./pubkeys/' + pubkeyfile, 'r')
    data = f.read().replace('-----BEGIN RSA PUBLIC KEY-----', '').replace('-----END RSA PUBLIC KEY-----', '')
    data = b64decode(data)
    pubkeys[pubkeyfile] = RSA.importKey(data)
    f.close()

for emailfile in emailfiles:
    f = open('./emails/' + emailfile, 'r')
    data = f.read()
    sender = re.findall('To: (.*)@dnc', data)[0]
    date = re.findall('Date: (.*)\n', data)[0]
    content = re.findall('Content: (.*)', data)[0]
    if not date in encrypted_emails:
        encrypted_emails[date] = {}
    encrypted_emails[date][sender] = int(content, 16)

message_content = False
for date in encrypted_emails:
    moduli = []
    remainders = []
    
    for x in encrypted_emails[date]:
        moduli.append(pubkeys[x].n)
        remainders.append(encrypted_emails[date][x])

    x = libnum.modular.solve_crt(remainders, moduli)
    x0 = gmpy.mpz(x)
    xr = x0.root(17)
    message = libnum.n2s(int(xr[0]))
    
    if not message_content:
        message_content = ['?'] * len(message)
    
    for i, c in enumerate(message):
        if c != '#':
            message_content[i] = c

print ''.join(message_content)
```

which outputs

```
Subject: My Fellow DNC Members
Content: Keep this safe <MISSING>1862866103431083493477241717117566609979097064670248011800478128293487053500169824960133057115553, that's the key we agreed on.
```

OK, so let us assume that the key mentioned in the message is the lower bits of the private exponent. There is a method to solve this problem. A script which implements this method can be found [here](https://github.com/grocid/CTF/tree/master/CSAW/2016#still-broken-box-400-p) and [here](https://grocid.net/2016/03/14/0ctf-equation/).

Unfortunately, the computation did not finish (e = 65537 takes some time to run, even multithreaded). Pity.