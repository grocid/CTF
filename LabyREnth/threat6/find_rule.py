from os import listdir
from os.path import isfile, join

def to_nibbles(data):
    out = []
    for byte in data:
        byte = ord(byte)
        upper = (0xf0 & byte) >> 4
        lower = byte & 0xf
        out += hex(upper)[2:]
        out += hex(lower)[2:]
    return ''.join(out)

filepath = 'yara2/'
fnames = [f for f in listdir(filepath) if isfile(join(filepath, f))] # get directory listing
f_data = []

st = '5153568b742414b9030000008bc633db99f7f93bd375048bc6eb1683fa0175058d4602eb0c83fa028d460174048b4424088d0c85' # guessed fixed point
counter = len(st)
data_indices = []

for fname in fnames:
    f = open(filepath + fname)
    print '[+] Processing', filepath + fname, 
    data = to_nibbles(f.read())
    data_pos = data.find(st)

    if data_pos != -1: # exclude files not relevant to us
        print '--> starting point found @', data_pos
        data_indices.append(data_pos)
        f_data.append(data)
    else:
        print '--> no starting point'

wildcards = 0

while True: # now search
    
    nib = ''
    match = True
    
    for hexstring, index in zip(f_data, data_indices):
        if nib == '':
            nib = hexstring[index + counter]
        else:
            if nib != hexstring[index + counter]:
                wildcards += 1
                st += '?'
                match = False
                break

    if match:
        st += hexstring[index + counter]
    counter += 1
    if wildcards > 52: # discrepancy threshold
        break
        
        
print '[+] Found signature:'
y = '' # format for yar-file
for i in range(0, len(st), 2):
    y += st[i:i+2] + ' '
print y[:-2] 