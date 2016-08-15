import re, dpkt, base64

f = open('dopefish_labyrinth.pcap' , 'rb')
pcap = dpkt.pcap.Reader(f)
list =[]

for ts, buf in pcap:
    result = re.search('GET(.*)HTTP/1.1', buf)
    if result != None:
        query = result.group(1) # just extract some different fields
        upper = re.search('php\?(.*)&', query).group(1)
        lower = re.search('[0-9]\?(.*)-', query).group(1)
        list.append(base64.b64decode((upper+lower)[::-1]).replace('317',''))

string = ''
for x in range(len(list[0])):
    for line in list:
        if line[x] not in ['W',';','.','V','\n']: # filter out gibberish
            string += line[x]

print string