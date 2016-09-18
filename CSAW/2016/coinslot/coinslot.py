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