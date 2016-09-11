
'''
publika parametrar: N, g, k

hemlig: x

A := 
x := hash(salt,email,password)
b := rand(1,N)
B := k * g^x + g^b (mod N)
u := hash(A,B)

S_s := (A * (g^x)^u)^b
K_s := hash(S_s)

'''



import hashlib, string, random, base64
from pwn import *

#s = socket.create_connection(('localhost', 3004))
s = remote('srpp.asis-ctf.ir', 22778)
#s = remote('localhost', 3005)

def Hash(*args):
    a = ':'.join(str(a) for a in args)
    return int(hashlib.sha256(a).hexdigest(), 16)

def send(str):
    print '[+] Sending', str
    s.send(str)

ssss = s.recvuntil('\n')[:4]
_,suffix,_,hashval,_ = s.recvuntil('\n').split('\"')
hashval = hashval[:-3]
email = 'admin@asis-ctf.ir'
vals = {}
g = 2
print '[+] Running proof of work...'

while True:
    while True:
        prefix = ''.join(random.choice(string.digits+string.ascii_letters) for i in range(4))
        if prefix not in vals:
            break
    vals[s] = 1
    if hashlib.sha512(prefix + suffix).hexdigest()[:len(hashval)] == hashval:
        break

s.send(prefix+'\n')
q = s.recvuntil('\n')
q = s.recvuntil('\n')
q = s.recvuntil('\n')
q = s.recvuntil('\n')
N = int(q.split()[6][1:-2])
send(email+','+str(2*N))
q = s.recvuntil('\n')
q = s.recvuntil('\n')
salt, B = q.split('\n')[0].split('(')[2].split(',')
salt = base64.b64decode(salt)
B = int(B[:-2])
q = s.recvuntil('\n')
m = Hash(0)
send(str(m)+'\n')
q = s.recvuntil('\n')
send(str(Hash(Hash(N) ^ Hash(g), Hash(email), salt, 2*N, B, Hash(0)))+'\n')
q = s.recvuntil('\n')
print q
