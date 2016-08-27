import numpy
from sage.all import *

alphabet = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}")
n = len(alphabet)

Zn = IntegerModRing(n)

secret  = [[54, 53, 28, 20, 54, 15, 12, 7],
          [32, 14, 24, 5, 63, 12, 50, 52],
          [63, 59, 40, 18, 55, 33, 17, 3],
          [63, 34, 5, 4, 56, 10, 53, 16],
          [35, 43, 45, 53, 12, 42, 35, 37],
          [20, 59, 42, 10, 46, 56, 12, 61],
          [26, 39, 27, 59, 44, 54, 23, 56],
          [32, 31, 56, 47, 31, 2, 29, 41]]

secret = matrix(Zn, secret).inverse()
ciphertext = "7Nv7}dI9hD9qGmP}CR_5wJDdkj4CKxd45rko1cj51DpHPnNDb__EXDotSRCP8ZCQ"

blocks = [ciphertext[i : i + secret.ncols()] for i in range(0, len(ciphertext), secret.ncols())]

plaintext = ''

for block in blocks:
    decrypted_block = secret * matrix(Zn, [alphabet.find(c) for c in block]).transpose()
    plaintext +=  ''.join(alphabet[int(i[0])] for i in decrypted_block)
    
print plaintext