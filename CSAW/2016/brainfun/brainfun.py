import numpy
from PIL import Image
blocks = 32
A = numpy.zeros((blocks, blocks))
B = numpy.zeros((blocks, blocks))
C = numpy.zeros((blocks, blocks))
D = numpy.zeros((blocks, blocks))
im = Image.open("brainfun.png") #Can be many different formats.
pix = im.load()
j = 512 / blocks
for x in range(0, blocks):
    for y in range(0, blocks):
        A[x][y] = pix[x * j + j / 2, 
                  y * j + j / 2][3] 

Q = []
out = ''
for row in A.astype('int'):
    Q += set(list(row))
    out += ''.join(chr(x) for x in row)

print 'Brainfuck? Brainfun?'
#print [chr(x) for x in set(Q)]
#print len(set(Q))
print out