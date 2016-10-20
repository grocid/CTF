# cornelius1

```
Please find Cthulhu's magic here.
Attachment: server.rb
P.S.: flag is the decrypted plaintext and is not in flagformat!
```
A web service has the following code running:

```ruby

require 'openssl'
require 'webrick'
require 'base64'
require 'json'
require 'zlib'
require 'pry'

def encrypt(data)
 cipher = OpenSSL::Cipher::AES.new(128, :CTR)
 cipher.encrypt
 key = cipher.random_key
 iv = cipher.random_iv
 cipher.auth_data = ""
 encrypted = cipher.update(data) + cipher.final
 return encrypted
end

def get_auth(user)
 data = [user, "flag:"+File.read("flag.key").strip]
 json = JSON.dump(data)
 zip = Zlib.deflate(json)
 return Base64.strict_encode64(encrypt(zip))
end

class Srv < WEBrick::HTTPServlet::AbstractServlet
 def do_GET(req,resp)
   user = req.query["user"] || "fnord"
   resp.body = "Hallo #{user}"
   resp.status = 200
   puts get_auth(user).inspect
   cookie = WEBrick::Cookie.new("auth", get_auth(user))
   resp.cookies << cookie
   return resp
 end
end

srv = WEBrick::HTTPServer.new({Port: 12336})
srv.mount "/",Srv
srv.start

```

We note that the server does the following: 

```ruby
 data = [user, "flag:"+File.read("flag.key").strip]
 json = JSON.dump(data)
 zip = Zlib.deflate(json)
```

Clearly, this is exploitable (as in the CRIME attack). By sending 'flag:' as user, we see that it has no effect on the length of the auth token. This is because the repetition causes the payload to compress better. As long as we have common pattern with the flag, it will get well-compressed.

If we guess one char at the time, we will very quickly determine the flag. It might be that in some settings, the will be no difference no matter what we send. Here, one has to guess or restructure the payload (see below). A Python code which finds the secret flag can be written briefly as:

```python

import requests, string, base64, binascii
flag = 'flag:'
# to get from 'flag:Mu7a' to 'flag:Mu7ai', you have to send 'flag:7a' and observe the differential
while True:
   print flag
   for x in string.printable:
       payload = {'user': flag + x}
       r = requests.get('https://cthulhu.fluxfingers.net:1505/', params=payload)
       if len(base64.b64decode(r.cookies['auth'])) == 30:
           flag += x
           break

```

This outputs, after some manual adjusting

```
Mu7aichede
```

# Cryptolocker

```
Oh no! Cthulhu's laptop was hit by ransomware and an important document was encrypted! But you have obtained the encryption script and it seems like the encryption is vulnerable...
Even tough you don't know the encryption password, can you still help recover the important ODT file?
```

The encryption code looks as follows

```python
#!/usr/bin/env python3
import sys
import hashlib
from AESCipher import *

class SecureEncryption(object):
   def __init__(self, keys):
       assert len(keys) == 4
       self.keys = keys
       self.ciphers = []
       for i in range(4):
           self.ciphers.append(AESCipher(keys[i]))

   def enc(self, plaintext): # Because one encryption is not secure enough
       one        = self.ciphers[0].encrypt(plaintext)
       two        = self.ciphers[1].encrypt(one)
       three      = self.ciphers[2].encrypt(two)
       ciphertext = self.ciphers[3].encrypt(three)
       return ciphertext

   def dec(self, ciphertext):
       three      = AESCipher._unpad(self.ciphers[3].decrypt(ciphertext))
       two        = AESCipher._unpad(self.ciphers[2].decrypt(three))
       one        = AESCipher._unpad(self.ciphers[1].decrypt(two))
       plaintext  = AESCipher._unpad(self.ciphers[0].decrypt(one))
       return plaintext

if __name__ == "__main__":
   if len(sys.argv) != 3:
       print("Usage: ./cryptolock.py file-you-want-to-encrypt password-to-use")
       exit()

   # Read file to be encrypted
   filename = sys.argv[1]
   plaintext = open(filename, "rb").read()

   user_input = sys.argv[2].encode('utf-8')
   assert len(user_input) == 8
   i = len(user_input) // 4
   keys = [ # Four times 256 is 1024 Bit strength!! Unbreakable!!
       hashlib.sha256(user_input[0:i]).digest(),
       hashlib.sha256(user_input[i:2*i]).digest(),
       hashlib.sha256(user_input[2*i:3*i]).digest(),
       hashlib.sha256(user_input[3*i:4*i]).digest(),
   ]
   s = SecureEncryption(keys)

   ciphertext = s.enc(plaintext)
   plaintext_ = s.dec(ciphertext)
   assert plaintext == plaintext_

   open(filename+".encrypted", "wb").write(ciphertext)

```

It takes a password of length 8 and (SHA-256-) hashes each two bytes into four keys. Then, the plaintext is encrypted four times, each time with different keys.

The size of the key space is 256² × 256² × 256² × 256². Now, obviously, we cannot brute force that. However, we know one thing. Except from the first plaintext, all ciphertexts have a length which is congruent to the block size. So, by decrypting the first encryption layer under 256² different keys, we can filter out all non-conforming results. We can define three sets A₄ := {|DEC(c, k₄)| (mod 32) = 0}, A₃ := {|DEC(DEC(c, k₄), k₃)| (mod 32) = 0} and finally A₂ := {|DEC(DEC(DEC(c, k₄), k₃), k₂)| (mod 32) = 0}. We are looking for the intersection between these sets.

Now each decryption takes quite a while, since they are large. What we do is to cut the ciphertext and keeping only a small part at the end. This will cause the ciphertext to decode incorrectly in the first block, but we don't really care about that. This makes decryption much faster and we are able to filter out candidates, and generate new ones from these in the subsequent layer. Some ugly code to solve it:

```python

   f = open('flag.encrypted', 'r')
   ciphertext = f.read()[-32*10:]
   decs = []

   alphabet = string.ascii_letters+string.digits

   print('hej')

   for i in alphabet:
       for j in alphabet:
           cipher = AESCipher(hashlib.sha256((i+j).encode('utf-8')).digest())
           out = AESCipher._unpad(cipher.decrypt(ciphertext))
           if len(out) == len(ciphertext)-32:
               print (i+j, len(out), len(ciphertext))
               decs.append(i+j)
   decs2 = []

   for x in decs:
       cipher = AESCipher(hashlib.sha256(str(x).encode('utf-8')).digest())
       cc = AESCipher._unpad(cipher.decrypt(ciphertext))

       for i in alphabet:
           for j in alphabet:
               cipher = AESCipher(hashlib.sha256(str(i+j).encode('utf-8')).digest())
               out = AESCipher._unpad(cipher.decrypt(cc))
               if len(out) == len(cc)-32:
                   decs2.append(i+j+x)

   decs3 = []

   for x in decs2:    
       cipher = AESCipher(hashlib.sha256(str(x)[-2:].encode('utf-8')).digest())
       cc = AESCipher._unpad(cipher.decrypt(ciphertext))

       cipher = AESCipher(hashlib.sha256(str(x)[:2].encode('utf-8')).digest())
       cc = AESCipher._unpad(cipher.decrypt(cc))

       for i in alphabet:
           for j in alphabet:
               cipher = AESCipher(hashlib.sha256(str(i+j).encode('utf-8')).digest())

               out = AESCipher._unpad(cipher.decrypt(cc))
               if len(out) == len(cc)-32:
                   print ([i+j+x], len(out))
                   decs3.append(i+j+x)


```

In the last step, we do the same trick. Looking at common ODT files, we note that most of the end with `0x00 0x00 0x00 0x00`. This happends not to be the case here. However, by slightly relaxing the filter and require only `0x00 0x00`, we get the key in the set. Then, we test each key resulting in such a plaintext (basically checking if it begins with `PK`). This finaly set is A₁ := {|DEC(DEC(DEC(DEC(c, k₄), k₃), k₂), k₁)| ends with `0x00 0x00`}. So, now we have computed A := A₄ ∩ A₃ ∩ A₂ ∩ A₁. For each element in this set, we determine if the decryption is an ODT file.

```python
   f = open('flag.encrypted', 'r')
   ciphertext = f.read()
   short_ciphertext = ciphertext[-32*10:]
   decs = []

   alphabet = string.ascii_letters+string.digits+'$<{}>'

   ctr = 0
   keys = []
   for subkey in possible_keys:
       ctr += 1
       print (subkey, subkey[-2:], subkey[-4:-2], subkey[:2], '{0}/{1}'.format(ctr, len(possible_keys.table)))

       cipher1 = AESCipher(hashlib.sha256(str(subkey[-2:])).digest())
       cipher2 = AESCipher(hashlib.sha256(str(subkey[-4:-2])).digest())
       cipher3 = AESCipher(hashlib.sha256(str(subkey[2:4])).digest())
       cipher4 = AESCipher(hashlib.sha256(str(subkey[:2])).digest())

       one = AESCipher._unpad(cipher1.decrypt(ciphertext))
       two = AESCipher._unpad(cipher2.decrypt(one))
       three = AESCipher._unpad(cipher3.decrypt(two))
       four = AESCipher._unpad(cipher4.decrypt(three))
       if four[0:2] == 'PK':
           print subkey

   print (keys)
```

This gives `Sg52WH4D`, which succesfully decrypts the cipertext and we get the flag

```
flag{v3ry_b4d_crypt0_l0ck3r}
```

# Maze

```
You just have to solve the maze here: Sounds easy, doesn't it ?
```

First, we need to get the credentials, which can be obtained by a HTTP-proxy bug. Then, we write a simple script to traverse the nodes. We use a breadth first algorithm:

```python
import urllib, urllib2, base64, re
base = 'https://cthulhu.fluxfingers.net:1507'

def req(path, data):
    request = urllib2.Request(base + path)
    base64string = base64.b64encode('%s:%s' % ('sup3rs3cr3tus3r', 'n0b0dyc4ngu3smyp4ssw0rd'))
    request.add_header("Authorization", "Basic %s" % base64string)   
    r = urllib2.urlopen(request, data).read()
    return r

r = req('', None)
prog = re.compile(r'<a href=([\w/.]*)>')
captcha = re.compile(r':<br>([\d *+-]*)=')
current_nodes = prog.findall(r)[:-1]
visited_nodes = []

while True:
    next_nodes = []
    for link in current_nodes:
        if link not in visited_nodes:
            print link, len(visited_nodes)
            r = req(link, None)
            if len(captcha.findall(r)) > 0:
                captcha_result = eval(captcha.findall(r)[0])
                form_data = {'result': captcha_result}
                params = urllib.urlencode(form_data)
                r = req(link, params)
            else:
                print r
            if len(prog.findall(r)) == 0:
                print r
            else:
                next_nodes += prog.findall(r)[:-1]
            visited_nodes.append(link)

    current_nodes = next_nodes
```

After running for what felt like an eternity (about 20 minutes), we find

```
/maze/s1y27hb8wgwc8jvk487c4j8w9jd5hdvk/ythfg4payo7egk49kh8ffocayqhj1gp8.php
```

which contains

```
FLAG{queried_g00d_y0u_h4v3}
```