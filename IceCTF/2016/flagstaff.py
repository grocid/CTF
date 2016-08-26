import socket, base64

def send(commands):
   s = socket.create_connection(('flagstaff.vuln.icec.tf', 6003))
   s.recv(1024)
   print s.recv(1024)
   for cmd in commands:
       print '>> Sending:', cmd
       s.send(cmd + '\n')
       data = s.recv(1024).strip('\n')
   s.recv(1024)
   return data

data = 'flag' + '\x0c' * 0xc
encrypted = send(['decrypt', base64.b64encode(data + data)])
c = base64.b64decode(encrypted)[0:16]
data = send(['secret', base64.b64encode(c + data)])
data = send(['decrypt', data])
print 'FLAG:', base64.b64decode(data)