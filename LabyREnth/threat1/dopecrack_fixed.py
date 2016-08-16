import re, dpkt, base64

f = open('dopefish_labyrinth.pcap' , 'rb')
pcap = dpkt.pcap.Reader(f)
list =['']*40

for ts, buf in pcap:
    result = re.search('GET(.*)HTTP/1.1', buf)
    if result != None:
        query = result.group(1) # just extract some different fields
        index = re.search('\/(.*)\.php', query).group(1)
        index = int(base64.b64decode(index))
        upper = re.search('php\?(.*)&', query).group(1)
        lower = re.search('[0-9]\?(.*)-', query).group(1)
        list[index] = base64.b64decode((upper+lower)[::-1]).replace('317','')

for i in range(10,40):
  print list[i][:-1]