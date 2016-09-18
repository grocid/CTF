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
        print ''.join(number[::-1])
        print 'Remaining unknown: {0} / {1}'.format(unknown, len(number))
        

N = 123541066875660402939610015253549618669091153006444623444081648798612931426804474097249983622908131771026653322601466480170685973651622700515979315988600405563682920330486664845273165214922371767569956347920192959023447480720231820595590003596802409832935911909527048717061219934819426128006895966231433690709 # Modulus
x = 96324328651790286788778856046571885085117129248440164819908629761899684992187199882096912386020351486347119102215930301618344267542238516817101594226031715106436981799725601978232124349967133056186019689358973953754021153934953745037828015077154740721029110650906574780619232691722849355713163780985059673037  # Ciphertext

e = 97


valid, faulty = [], []
msg = 2
f = open('sigs2.txt', 'r')

for line in f:
    sig = int(line)
    if ver(sig) == 2: valid.append(sig)
    else: faulty.append(sig)

print '[+] Found {0} valid and {1} faulty signatures!'.format(len(valid), len(faulty))

#d = test_exponent_faults()
#test_crt_faults()

#print libnum.n2s(pow(x, d, N))

print len('000001100001101000010001101110010111100000001011001011000101010111100100111011111011101010111010110010111111001001100111001010000111110100010011001100001001110000001011101100000100111110100011000000101100011110110010110100010111000110011101000111010011011100111001101110001110110011111010111011101101')

d_p = int('000001100001101000010001101110010111100000001011001011000101010111100100111011111011101010111010110010111111001001100111001010000111110100010011001100001001110000001011101100000100111110100011000000101100011110110010110100010111000110011101000111010011011100111001101110001110110011111010111011101101', 2)

print d_p


p =11508259255609528178782985672384489181881780969423759372962395789423779211087080016838545204916636221839732993706338791571211260830264085606598128514985547
q = N/p

d = libnum.modular.invmod(e, (p-1)*(q-1))

print libnum.n2s(pow(x, d, N))


