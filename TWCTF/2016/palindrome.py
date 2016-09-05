import socket, copy
words = ['tzztxgumeg', 'zfiqo', 'xdgemugx', 'dx', 'oqifz']

def palindrome(words, left, right, sl, sr, i):
    #print i, left + ' '  + right
    if len(words) > 1:
        for i in range(0,len(words)):
            for j in range(0,len(words)):
                l = words[i]
                r = words[j]
                if i != j:
                    right_p = r + right
                    left_p = left + l
                    sl_p = sl + ' ' + l
                    sr_p = r + ' ' + sr
                    p = min(len(right_p), len(left_p))
                    if left_p[:p] == right_p[::-1][:p]:
                        M = copy.copy(words)
                        M.remove(l)
                        M.remove(r)
                        y = palindrome(M, left_p, right_p, sl_p, sr_p, i+1)
                        if y != False:
                            return y
    elif len(words) == 1:
        print "HHHHHHHH", words
        y = left + words[0] + right
        if y == y[::-1]:
            return sl + ' ' + words[0] + ' ' + sr
        else:
            return False
    else:
        y = (left + right)
        if y == y[::-1]:
            return (sl + ' ' + sr)
        else:
            return False
    return False
            

s = socket.create_connection(('ppc1.chal.ctf.westerns.tokyo', 31111))
print s.recv(1024)
data = s.recv(1024)

while True:
    for line in data.split('\n'):
        ll = line.split(' ')
        if ll[0] == 'Input:':
            uu = palindrome(ll[2:],'','','','',0)
            s.send(uu + '\n')
    data = s.recv(1024)
    print data
    if data == '':
        break