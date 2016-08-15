import re, dpkt

data = ['\x00']*19550

count = 0
residue = ''
f = open('fragments.pcap' , 'rb')

pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:

    if len(buf) > 250 and len(buf) < 1000: # some threshold

        result = re.search('Content-Length: (.*)\r\n', buf)
        
        if result != None: 
            content_length = int(result.group(1))
            
        result = re.search('bytes (.*)-', buf)
        
        if result != None: 
            position = int(result.group(1))
            data[position:position+content_length] = buf[-content_length:]

g = open('ssl_session_to_google.pcap', 'wb')
g.write(''.join(data))
