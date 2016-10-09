import base64, struct
from Crypto.Cipher import AES
from pwn import *
import numpy, libnum

forged_table = {1: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 2: '\xdd\xa2[\x12!\x98W\xc3\xe6\x18\x9b\x9e\xfaY\xb0C', 3: '\xe8\x1e\xf2\r\xa1\x8c\x08\xa1\xb2\xd6\xe3\xa9\xfa\xf3\x06\xa7', 4: 'g;c\xfd\xa8H\x9a\xa9\x90\xfa\xafEZh\x9b\xb3', 5: 'D\xea{\x14\t\x8cA\xe2C\xcc\xbf\xf3v\x04C\xcd', 6: '\xedFA\xe4\x89M\xc82\xdd{\x89\xc7+\x83)J'}

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


context.log_level = 'error'
s = remote('challenges.hackover.h4q.it', 1415)
counter = 1

while True:
    s.recvuntil('My dice roll: ')
    roll = s.recvuntil('\n').strip('\n')
    binroll = base64.b64decode(roll)

    # send data
    enckey =  '\x00'*16
    cipher = AES.new(enckey, AES.MODE_ECB)
    payload = '\x00'+libnum.n2s(1)+'\x00'*14
    payload = cipher.encrypt(payload)
    s.send(base64.b64encode(payload) + '\n')

    s.recvuntil('My key:')
    key = s.recvuntil('\n').strip('\n')
    binkey = base64.b64decode(key)
    cipher = AES.new(binkey, AES.MODE_ECB)

    got_roll = libnum.s2n(cipher.decrypt(binroll)[:2])
    s.send(base64.b64encode(forged_table[7 - got_roll]) + '\n')
    counter += 1
    if counter == 33:
        print s.recvuntil('\n')
        break


