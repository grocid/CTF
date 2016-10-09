#Challenges
## rollthedice
```
The new cyber casinos are using high speed digital cyber dices to provide 
the best available gaming experience. Play a brand new dice game at new 
levels and win. Please note that you have to upgrade to blockchain 3.0 to 
receive your profits via a smart contract 2.0.

nc challenges.hackover.h4q.it 1415
```

When connecting, you get something like

```
	Welcome to rollthedice!
	We use a cool cryptographic scheme to do fair dice rolls.
	You can easily proof that I don't cheat on you.
	And I can easily proof that you don't cheat on me
	
	Rules are simple:
	Roll the opposite side of my dice roll and you win a round
	Win 32 consecutive rounds and I will give you a flag.
```
 
Client and server each picks a secret random key k₁ and k₂. Each party then encrypts a dice roll rᵢ ∈ ℤ₆ with their secret random key, giving cᵢ ← Enc(rᵢ, kᵢ). First, server announces its encrypted dice roll and then the client does the same. After that, server annonunces its key k₂, after which the client announces its key k₁. Now all parties know the dice rolls and can check whether the sum up to 7.

The problem is how the dice rolls are encoded and decoded. Basically, a dice roll is stored as a uint16 the upper part of the plaintext. The remaing parts contain only random junk. So, we should be able to commit to the very same ciphertext at all times and pick keys depending on what dice roll the server got. Assume that we are sending 1 for the all-zero key. Then, with this particular ciphertext, we need to find a k such that it decrypts to 2, 3, and so on. Once all have been found we can cheat in this commitment scheme. Here is some Python code to achieve this part:


```
def build_forged_table():
    global forged_table
    enckey =  '\x00'*16
    cipher = AES.new(enckey, AES.MODE_ECB)
    payload = '\x00'+libnum.n2s(1)+'\x00'*14
    payload = cipher.encrypt(payload)
    forged_table[1] = enckey
    print '[ ] Running forging procedure...'
    while len(forged_table.keys()) < 7:
        enckey = os.urandom(16)
        cipher = AES.new(enckey, AES.MODE_ECB)
        roll = libnum.s2n(cipher.decrypt(payload)[:2])
        if roll < 7 and roll > 1 and roll not in forged_table.keys(): forged_table[roll] = enckey
```

It takes a few seconds to run...

```python
forged_table
{1: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 
 2: '\xdd\xa2[\x12!\x98W\xc3\xe6\x18\x9b\x9e\xfaY\xb0C', 
 3: '\xe8\x1e\xf2\r\xa1\x8c\x08\xa1\xb2\xd6\xe3\xa9\xfa\xf3\x06\xa7', 
 4: 'g;c\xfd\xa8H\x9a\xa9\x90\xfa\xafEZh\x9b\xb3', 
 5: 'D\xea{\x14\t\x8cA\xe2C\xcc\xbf\xf3v\x04C\xcd', 
 6: '\xedFA\xe4\x89M\xc82\xdd{\x89\xc7+\x83)J'}
```

Now, its is very simple to win. We pick the key from `forged_table` and, hence we can win each round with no failing probability at all. Great!

```
Your key: You win! How was that possible? 
However, here is your flag: hackover16{HowAboutAuthenticatedEncrYption?}
```
## guessr
```
We apologize for this challenge's name. Adding "r"s to the end is so cyber 2.0.
We will soon publish a new name that fits the cyber 3.0! In the meantime you 
can guess our new namesome random numbers. Stay tuned!

nc challenges.hackover.h4q.it 64500
```

This is basically a truncated linear conguential generator with parameters m = 2³¹, a = 7⁶ and b = 5. Given a starting seed x, next value is computed as x ← ax + b (mod m). Then, the outputted value is y = {x (mod 100)} + 1. So, how do you go on and solve this? Well, one way would be lattice reduction... but 2³¹ is not that large. If we sample a few values (the RNG will not re-seed if we are wrong so we can find this by guessing). Then, we can generate the whole sequence and check for matches.

This can be achieved as follows

```python
seq = [41, 90, 27, 12, 45, 50, 67, 16] # example of found sequence

r = RNG(*ARGS)
j = 0
for i in range(0, 2**31):
    r.step()
    c = r.get_val(1,101)
    if c == seq[j]:
        j += 1
        if j == len(seq): 
            break
    else: j = 0
```

Alright, so we got the flag!

```
hackover16{SoRandomLOL}
```

## ish_{1,2} (insecure shell)

### Part one
```
This cyber protocol provides high confidentiality and integrity for cloud 
environments by implementing a new challenge response scheme. It is easy 
to integrate into your cloud applications and uses well-known cryptographic 
primitives which have a long history of protecting the cyber space. Rely on 
our business solution in all your authentication issues 
--we won't disappoint you, promise!

nc challenges.hackover.h4q.it 40804
```

In this challenge-response protocol, the client and the server share a common key k. First, the client generates a random nonce r₁ and sends it to the server. The server encrypts the nonce with the key k and sends y₁ = Enc(r₁, k) the client. Then client may then check decrypted data and nonce match. Then the server generates a random nonce r₂ and sends to the client, which is asked to encrypt with key k. The client computes y₂ = Enc(r₂, k) and sends to server. When received, the server can check that they match.

There is an obvious flaw here. What if we establish two connections to the server (i.e., two clients running parallel)? Since the challenge-response is symmetric, we can make the server do all the work. 

1. Client A connects to server. Sends a nonce r₁ and accepts any answer from the server. It reads the challenge nonce r₂.
2. Client B connects to server. Receives r₂ from client A. Sends it a challenge to the server. Then answer is y₂ = Enc(r₂, k). Client B forwards this to client A.
3. Client A can now answer the servers challenge with y₂ = Enc(r₂, k) that it received from client B.
4. We are authenticated!

Here, in Python

```python
# connect to server
s = remote('challenges.hackover.h4q.it', 40804)
# connect to server second time
g = remote('challenges.hackover.h4q.it', 40804)

# send a random nonce and blindly accept it
data = 'Nonce:' + hexlify(get_random(16))
send(s, data)
recv(s)
send(s, 'ok')
nonce = recv(s)[len('Nonce:'):] # obtain server challenge

# ask server for response to server challenge
send(g, 'Nonce:' + nonce)
data = recv(g)

# send server's own response to server
send(s, data)
print recv(s)
send(s, 'get-flag')
print recv(s)
```

Running it gives

```
hackover16{reflectAboutYaL1fe}
```

### Part two
```
Cyber F*ck! We are really sorry ... it will not happen again! We fired our 
cyber security specialist -- all his Cyscu certificates were fake and Human 
Resources 0.7 did not find out ... Download this new version. 
There will be no more issues, big promise!

nc challenges.hackover.h4q.it 15351
```

The same protocol is implemented, but the commands and their responses are encrypted with the key k (see previous part).

We can re-use our approach (and code) from the previous part. Now, we note that everything is encrypted with AES-CBC (we did not mention this before, since it was not really relevant).

Since we may alter the IV, we can use this to obtain an encrypted version of the command `get-flag`. The nonce has the format `Nonce:[32 hexchars]`. Let us set a nonce as follows:

```python
r = 'Nonce:' + hexlify('\x00'*16)
cmd =  'get-flag;' + ' ' * (16 - len('get-flag;'))
```

We get an encrypted nonce Enc(r, k) from the server. By XOR:ing the IV part with r ⊕ cmd, we can flip the ciphertext. Remember that for the first block of AES-CBC, it holds that

Dec(Enc(x₁ ⊕ y₁, IV), k) = C⁻¹(C(x₁ ⊕ y₁ ⊕ IV), IV) = C⁻¹(C(x₁ ⊕ IV), IV ⊕ y₁) = Dec(Enc(x₁, IV ⊕ y₁)).

Therefore, we can change IV

```python
iv = xor(xor(enc_r[:16], cmd), r[:16])
```

so that it decrypts to `get-flag; ...`. Great! The server willingly sends us the flag... but it is encrypted. Hm... let us a look at the cmd-handler function:

```python
def cmd_handler(cmd):
    print "executing command: %s" % cmd
    ret = ""
    for c in cmd.split(";"):
        c = c.split(" ")
        if c[0] == "get-flag":
            ret += flag
        elif c[0] == "time":
            time.strftime("%b %d %Y %H:%M:%S")
        elif c[0] == "echo":
            ret += " ".join(c[1:])
        elif c[0] == "rand":
            ret += "%d" % random.randrange(2**32)
        else:
            ret += "unknown command"
        ret += "\n"
    return ret
```

There is an interesting behaviour here. If we can use the same idea as when we forged the encrypted command to actually guess the response, then we are done. I guess you could think of it as a padding oracle attack. So, how do we leak information? Well, there are many ways of doing it, but the most efficient one is to exploit the char `;`. Since `;;;;` will be interpreted as four unknown commands, the response will be much longer (we will get four 'unknown command' responses instead of one). So, among all guesses of the flag only one will XOR to `;`. This response will be longer than other responses (by one block).

```python
block = 0
enc_flag = enc_flag[16 * block:]
len_dict = {}
partial_flag = ''
while len(partial_flag) < 16:
    for a in string.uppercase+string.lowercase+string.digits+'}?':
        modifier = partial_flag + a
        send(s, xor(xor(enc_flag[:len(modifier)], payload), modifier) + enc_flag[len(modifier):])
        len_dict[len(recv(s))] = a
    partial_flag += len_dict[max(len_dict.keys())]
    print partial_flag
```
Running the final block, we get

```
T
Tr
Tru
Trus
Trust
TrustP
TrustPr
TrustPr0
TrustPr0m
TrustPr0m1
TrustPr0m1s
TrustPr0m1se
TrustPr0m1ses
TrustPr0m1ses?
TrustPr0m1ses?}
TrustPr0m1ses?}?
```

All and all, we have

```
hackover16{DoYouTrustPr0m1ses?}
```

## qr_code
```
Today cyber information is accessible in various ways. You can print them 
on e-paper, transmit them via cyber signals or use qr codes on classic 
paper! While e-paper is bronze and cyber signals are silver the best one -
qr codes - are gold! Their influence factor on cyber humans is the highest
since smartphones 2.0 are used all the time. But to read our qr code, you
require a smartphone 3.0 with the newest cryptography schemes trending 
now. Upgrade as soon as possible to get secure qr codes!
```

The encryption of this scheme is done as follows:

```python
def encrypt(pub, plaintext):

    def randg(n):
        y = gmpy2.mpz_random(rs, n)
        while gmpy2.gcd(y, n) != 1:
            y = gmpy2.mpz_random(rs, n)
        return y

    x, n = pub
    ciphertext = [(randg(n)**2 * x**b) % n
                  for b in plaintext]
    return ciphertext
```

Here, b is binary digit. So, if b = 0, the ciphertext is a quadratic residue. If b = 1, then it is not. There is really no way of breaking this easily, since quadratic residues are hard over a composite number n. However, if we can factor n, then it is easy.

Let us look how the key is generated:

```python
def keygen(size):
    rs = gmpy2.random_state(int(time.time()))
    p = gmpy2.next_prime(gmpy2.mpz_urandomb(rs, size))
    while p % 4 != 3:
        p = gmpy2.next_prime(p)
    q = gmpy2.next_prime(p)
    while q % 4 != 3:
        q = gmpy2.next_prime(q)
    n = p*q
    x = n-1
    return (x, n), (p, q)

pub, _ = keygen(2048)
```

So, the product n is 4096. Not very factorable. But take a look at this line

```python
rs = gmpy2.random_state(int(time.time()))
```

Very deterministic and the search space is not too hard, since it is in seconds. We have the timestamp `1475784906` of the generated file!

```python
def cyberhack_key():
    file_unix_timestamp = 1475784906
    while True:
        rs = gmpy2.random_state(start_val)
        p = gmpy2.next_prime(gmpy2.mpz_urandomb(rs, 2048))
        while p % 4 != 3:
            p = gmpy2.next_prime(p)
    
        if n % p == 0:
            print p
            break
        start_val -= 1
```

Great, so we find that 
```
p = 22250306827784715733283062128193677290021836024300489570709599202115926462302919976104520475770620608163557273901249985850005137090439882327585236665684669394670465240878675379943769961383455883823553180768037439715655143722265675380059231411902916425879836917950398675033311091214755225333868591298970375872242585296609513792539237228378437137800519388754607571027221647878664443668547789406536838722872829498112769424741955285673756857212860339558767970041783444629359810777280525857414547435135414691954819332038557708029354617237786225851984032666165772457515709803023490987886473030798730615844852872155726221247
q = 22250306827784715733283062128193677290021836024300489570709599202115926462302919976104520475770620608163557273901249985850005137090439882327585236665684669394670465240878675379943769961383455883823553180768037439715655143722265675380059231411902916425879836917950398675033311091214755225333868591298970375872242585296609513792539237228378437137800519388754607571027221647878664443668547789406536838722872829498112769424741955285673756857212860339558767970041783444629359810777280525857414547435135414691954819332038557708029354617237786225851984032666165772457515709803023490987886473030798730615844852872155726222747
```
They are very close... in fact q - p = 1500. Obviously, we could have found this in another way... but yeah. We got it, so never mind. What remains is to write the decryption routine.

```python
    import scipy.misc, numpy
    from libnum.sqrtmod import jacobi
    A = []
    
    for i in range(0, 37):
        b = []
        for j in range(0, 37):
            s = int(f.readline())
            if jacobi(s,p) == 1:
                b.append(0)
            else:
                b.append(1)
        A.append(b)
        
    scipy.misc.imsave('outfile.jpg', numpy.array(A))
```

We use the Jacobi symbol implementation of libnum, which under prime modulus is a Legendre symbol.


![QR](qr.png)


or decoded

```
hackover16{Qu4dr471c_R3s1du3_c0d35} 
```

#Conclusion
I really liked this CTF, with a fun crypto problems. I wish I had some more time to spend on it.