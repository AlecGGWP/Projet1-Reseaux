import pyshark
import dns.resolver
# need pyshark & dnspython to run
# python3 -m pip install --user pyshark
# python3 -m pip install --user dnspython

# Change inside cap variable the path to your package or others available in the record.
cap = pyshark.FileCapture('record/Appel+PartageEcran.pcapng')

# Change to the name of your app to filter it.
filtre='microsoft-teams'

def filtrer_pack(packet):
    return filtre in packet

def by_numb(setts):
    return setts[1]

#Apply the filter on the FileCapture.
cap.apply_on_packets(filtrer_pack)

#Variable counter.
ipv4 = 0
ipv6 = 0
udp = 0
tcp = 0
i = 0
dns_names = set()
auth_servers = set()

#Count & Filter the data
for packet in cap:

    if 'udp' in packet:
        udp+=1
    elif 'tcp' in packet:
        tcp+=1

    if 'ip' in packet:
        ipv4+=1
    elif 'ipv6' in packet:
        ipv6+=1

    if 'dns' in packet:

        if packet.dns.qry_name:
            domain = str(packet.dns.qry_name).rstrip('.')
            if domain not in auth_servers:
                try:
                    answer = dns.resolver.resolve(domain, 'NS')
                    auth_servers.add((domain,i))
                except:
                    pass

            dns_names.add((str(packet.dns.qry_name).rstrip('.'),i))
        elif packet.dns.resp_name:
            dns_names.add((str(packet.dns.resp_name).rstrip('.'),i))
        i+=1

print("Nombres IPV4:",ipv4,"\n")
print("Nombres IPV6:",ipv6,"\n")

print("Nombre DNS:",len(dns_names))
print("DNS_NAMES:",sorted(dns_names,key=by_numb),"\n")

print("Nombres AUTH_Servers:",len(auth_servers))
print("AUTH_SERVERS:",auth_servers,"\n")

print("Nombres TCP:",tcp)
print("Nombres UDP:",udp)