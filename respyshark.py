import pyshark
import dns.resolver
# need pyshark & dnspython to run
# python3 -m pip install --user pyshark
# python3 -m pip install --user dnspython

# Change inside cap variable the path to your package or others available in the record.
cap  = pyshark.FileCapture('record/Appel+PartageEcran.pcapng')
cap2 = pyshark.FileCapture('record/EnvoieFichier.pcapng')
cap3 = pyshark.FileCapture('record/MessageRecordSpam.pcapng')
cap4 = pyshark.FileCapture('record/Video+Partage.pcapng')
packagelist = [cap,cap2,cap3,cap4]


# Change to the name of your app to filter it.
filtre='microsoft-teams'

def filtrer_pack(packet):
    return filtre in packet

def by_numb(setts):
    return setts[1]

#Apply the filter on the FileCapture.
cap.apply_on_packets(filtrer_pack)
cap2.apply_on_packets(filtrer_pack)
cap3.apply_on_packets(filtrer_pack)
cap4.apply_on_packets(filtrer_pack)

#Variable counter.
ipv4 = 0
ipv6 = 0
udp = 0
tcp = 0
i = 0
type_a = 0
type_aaaa = 0
type_CNAME = 0
type_ns = 0
dns_names = set()
auth_servers = set()

#auth2_servers = set()
#dns2_names = set()


#Count & Filter the data
#Uncheck auth2_servers and dns2_names variables + inside the loop
#To get the DNS call order.

for capture in packagelist:

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
            if packet['DNS'].qry_type == '1':type_a+=1
            if packet['DNS'].qry_type == '2':type_ns+=1
            if packet['DNS'].qry_type == '5':type_CNAME+=1
            if packet['DNS'].qry_type == '28':type_aaaa+=1
            if packet.dns.qry_name:
                domain = str(packet.dns.qry_name).rstrip('.')
                if domain not in auth_servers:
                    try:
                        answer = dns.resolver.resolve(domain, 'NS')
                        #auth2_servers.add((domain,i))
                        auth_servers.add(domain)
                    except:
                        pass
                #dns2_names.add((domain,i))
                dns_names.add(domain)
            elif packet.dns.resp_name:
                print("yes")
                #dns2_names.add((str(packet.dns.resp_name).rstrip('.'),i))
                dns_names.add(str(packet.dns.resp_name).rstrip('.'))
            i+=1


print("Nombres IPV4:",ipv4)
print("Nombres IPV6:",ipv6)
print("Nombre DNS:",len(dns_names))
print("Nombre A",type_a)
print("Nombre AAAA",type_aaaa)
print("Nombre CNAME",type_CNAME)
print("Nombre NS",type_ns)
print("Nombres AUTH_Servers:",len(auth_servers))
print("Nombres TCP:",tcp)
print("Nombres UDP:",udp)

print("DNS_NAMES:",sorted(dns_names,key=by_numb),"\n")
print("AUTH_SERVERS:",auth_servers,"\n")
