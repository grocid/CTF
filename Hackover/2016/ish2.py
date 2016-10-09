from pwn import *
from binascii import hexlify, crc32
import string

def send(s, data):
    try:
        s.send(struct.pack('!h', len(data)))
        s.send(data)
    except:
        os.kill(os.getpid(), 9)

def recv(s):
    try:
        l = struct.unpack('!h', s.recv(2))[0]
        data = s.recv(l)
    except:
        os.kill(os.getpid(), 9)
    return data

def xor(a, b):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

def encrypt(message, key):
    iv = hashlib.md5(struct.pack('>i', crc32(message))).digest()
    aes = AES.new(key, AES.MODE_CBC, iv)
    padlen = 15 - (len(message) % 16)
    padding = "X"*padlen + chr(padlen+1)
    return iv + aes.encrypt(message + padding)


def decrypt(cipher, key):
    iv = cipher[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    plain = aes.decrypt(cipher[16:])
    return plain[:-ord(plain[-1])]

def get_random(n):
    with open("/dev/urandom", "r") as f:
        data = f.read(n)
    return data

s = remote('challenges.hackover.h4q.it', 15351)
g = remote('challenges.hackover.h4q.it', 15351)

sdata = 'Nonce:' + hexlify('\x00'*16)
cmd =  'get-flag;' + ' ' * (16 - len('get-flag;'))
send(s, sdata)
enc_nonce = recv(s)
send(s, 'ok')
nonce = recv(s)[len('Nonce:'):]
send(g, 'Nonce:' + nonce)
data = recv(g)
send(s, data)
print recv(s)

iv = xor(xor(enc_nonce[:16], cmd), sdata[:16])
send(s, iv + enc_nonce[16:])
enc_flag = recv(s)
payload = ';'*16

enc_flag = enc_flag[16:]
len_dict = {}
partial_flag = ''
while len(partial_flag) < 16:
    for a in string.uppercase+string.lowercase+string.digits+'}?':
        modifier = partial_flag + a
        send(s, xor(xor(enc_flag[:len(modifier)], payload), modifier) + enc_flag[len(modifier):])
        len_dict[len(recv(s))] = a
    partial_flag += len_dict[max(len_dict.keys())]
    print partial_flag



