from pwn import *
sigs = []
f = open('sigs.txt', 'a')
s = remote('crypto.chal.csaw.io', 8002)
modulus = 0
for i in range(0, 10000):
    s.recvuntil('Input an number(0~9999) to be signed:')
    s.send('2\n')
    data = s.recvuntil('\n')
    if modulus == 0:
        modulus = data.split()[1].split(':')[1].strip(',')
        print 'N = ', modulus
    if modulus != data.split()[1].split(':')[1].strip(','):
        print "MODULUS DIFFER!"
    f.write(data.split()[0].split(':')[1].strip(',')+'\n')
    s.recvuntil('Sign more items?(yes, no):')
    s.send('yes\n')