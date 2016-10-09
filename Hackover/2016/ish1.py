from pwn import *
from binascii import hexlify, crc32

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

'''hackover16{reflectAboutYaL1fe}'''
