import libnum
from fractions import gcd

def ver(s): return pow(s, e, N)

def test_crt_faults():
    print '[+] Testing faults in CRT...'

    for sig in faulty:
        ggcd = gcd(ver(sig) - msg, N)
    
        if ggcd > 1:
            print "[!] Found factor {0}".format(ggcd)
            break
        
        for fsig in faulty:
            if fsig != sig:
                # try to detect constant errors
                ggcd = gcd(N + ver(sig) - ver(fsig), N)
                ggcd = ggcd * gcd(ver(sig - fsig), N)
                if ggcd > 1:
                    print "[!] Found factor {0}".format(ggcd)
                    break
    if ggcd == 1:
        print '[-] No factors found...'

def test_exponent_faults():
    print '[+] Generating lookup...'
    
    number = ['?']*1024
    look_up = {pow(msg, pow(2,i), N) : i for i in range(0,1024)}
    valid_inv = libnum.modular.invmod(valid[0], N)
    
    print '[+] Looking for matches and recovering secret exponent...'

    for sig in faulty:
        st = (sig * valid_inv) % N
        
        if st in look_up: 
            number[look_up[st]] = '0'
        st = (libnum.modular.invmod(sig, N) * valid[0]) % N
        
        if st in look_up: 
            number[look_up[st]] = '1'
            
    unknown = number.count('?')
    
    if unknown == 0:
        d = int(''.join(number[::-1]), 2)
        
        print 'Secret exponent is: {0}'.format(d)
        print 'Check:', valid[0] == pow(msg, d, N)
        
        return d
    else:
        print '[+] Recovered bits'
        print ''.join(number)
        print 'Remaining unknown: {0} / {1}'.format(unknown, len(number))

N = 172794691472052891606123026873804908828041669691609575879218839103312725575539274510146072314972595103514205266417760425399021924101213043476074946787797027000946594352073829975780001500365774553488470967261307428366461433441594196630494834260653022238045540839300190444686046016894356383749066966416917513737 # Modulus
x = 19692422036782235398514555370081641811137305764564550834181151078007589826182210598961838126327403135461243782786057905195601375878137918933102276514209370988629276099804808840592900935798892808089393579394423786773939020570228687747030752462506451387793749298546229686125689926614969193166519141539393011964  # Ciphertext

e = 0x10001

valid, faulty = [], []
msg = 2
f = open('sigs.txt', 'r')

for line in f:
    sig = int(line)
    if ver(sig) == 2: valid.append(sig)
    else: faulty.append(sig)

print '[+] Found {0} valid and {1} faulty signatures!'.format(len(valid), len(faulty))

d = test_exponent_faults()
#test_crt_faults()

print libnum.n2s(pow(x, d, N))



