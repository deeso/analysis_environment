import io
from scapy import plist
from scapy.all import *
from dpkt.pcap import Reader


# class that reads in memory pcap and dumps the packets
class ReadPcap(object):

    def __init__(self, pcap_bytes):
        self.pkt_data = self.read_packets(pcap_bytes)
        self.pkts = [i[1] for i in self.pkt_data]

    @classmethod
    def read_packets(cls, pcap_bytes):
        packet_data = {}
        fdesc = io.BytesIO(pcap_bytes)
        pcap = Reader(fdesc)
        pkt_data = [(k,Ether(v)) for k,v in pcap.readpkts()]
        return pkt_data

    @classmethod
    def ip_pkts(cls, pkts):
        return [i for i in pkts if IP in i[1]]

    @classmethod
    def transport_pkts(cls, pkts):
        return [i for i in pkts if TCP in i[1] or UDP in i[1]]    

    @classmethod
    def udp_pkts(cls, pkts):
        return [i for i in cls.ip_pkts(pkts) if UDP in i[1]]        

    @classmethod
    def tcp_pkts(cls, pkts):
        return [i for i in cls.ip_pkts(pkts) if TCP in i[1]]

    @classmethod
    def http_pkts(cls, pkts):
        return cls.tcp_service(80, pkt_data)

    @classmethod
    def https_pkts(cls, pkts):
        return cls.tcp_service(443, pkt_data)

    @classmethod
    def dns_pkts(cls, pkt_data):
        return cls.udp_service(53, pkt_data)

    def http(self):
        return self.tcp_service(80, self.pkt_data)

    def https(self):
        return self.tcp_service(443, self.pkt_data)

    def dns(self):
        return self.udp_service(53, self.pkt_data)

    def smtp(self):
        return self.tcp_service(25, self.pkt_data)

    @classmethod
    def service(cls, port, pkt_data):
        pkt_data = cls.transport_pkts(cls.pkt_data)
        pkts = []
        for ts, pkt in pkt_data:
            if UDP in pkt and \
               (pkt[UDP].sport == port or pkt[UDP].dport == port):
               pkts.append(pkt)
            elif TCP in pkt and \
               (pkt[TCP].sport == port or pkt[TCP].dport == port):
               pkts.append(pkt)
        return cls.plist(pkts)

    @classmethod
    def tcp_service(cls, port, pkt_data):
        pkt_data = cls.tcp_pkts(pkt_data)
        pkts = []
        for ts, pkt in pkt_data:
            if TCP in pkt and \
               (pkt[TCP].sport == port or pkt[TCP].dport == port):
               pkts.append(pkt)
        return cls.plist(pkts)

    @classmethod
    def udp_service(cls, port, pkt_data):
        pkt_data = cls.udp_pkts(pkt_data)
        pkts = []
        for ts, pkt in pkt_data:
            if UDP in pkt and \
               (pkt[UDP].sport == port or pkt[UDP].dport == port):
               pkts.append(pkt)
        return cls.plist(pkts)

    @classmethod
    def plist(self, pkts=None):
        return plist.PacketList(pkts)


class MapDnsNames(object):
    DNS_TYP_STR = scapy.layers.dns.dnstypes
    DNS_STR_TYP = {v:k for k,v in DNS_TYP_STR.items()}

    @classmethod
    def dns_info_from_pkt_data(cls, pkt_data):
        dnsps = ReadPcap.udp_service(53, pkt_data)
        return cls.from_pslist(dnsps)

    @classmethod
    def dns_info_from_pslist(cls, dnsps):
        dns_rsps = []
        dns_rsp = [i for i in dnsps if DNS in i and i.sport == 53]

        for dr in dns_rsp:
            rsp = dr[DNS]
            qds = [i.fields for i in rsp.fields['qd']]
            for qd in qds:
                qd['type'] = cls.DNS_TYP_STR[qd['qtype']]
                qd['class'] = cls.DNS_TYP_STR[qd['qclass']]

            ans = []
            if not rsp.fields['an'] is None:
                ans = [i.fields for i in rsp.fields['an']]
            for an in ans:
                an['rtype'] = an['type'] 
                an['type'] = cls.DNS_TYP_STR[an['type']]
                an['class'] = cls.DNS_TYP_STR[an['rclass']]

            dns_rsps.append({'answer':ans, 'query':qds})

        return dns_rsps

    @classmethod
    def dns_resolutions_from_pkt_data(cls, pkt_data):
        return cls.dns_resolutions_from_pslist(cls.dns_info_from_pkt_data(pkt_data))

    @classmethod
    def dns_resolutions(cls, dnsps):
        def to_str(i):
            if isinstance(i, bytes):
                return i.decode('utf8').strip('.')
            return str(i).strip('.')

        dns_rsps = cls.dns_info_from_pslist(dnsps)

        srvs = {}
        cnames = {}
        in_to_a = {}
        a_to_in = {}

        unanswered = set()

        for info in dns_rsps:
            query = info['query']
            answer = info['answer']

            if len(answer) == 0:
                for q in query:
                    unanswered.add(to_str(q['qname']))

            for a in answer:
                t = a['type']
                if t in ['A', 'AAAA']:
                    rdata = to_str(a['rdata'])
                    rname = to_str(a['rrname'])
                    if not rname in a_to_in:
                        a_to_in[rname] = []
                    if not rdata in in_to_a:
                        in_to_a[rdata] = []

                    if not rdata in a_to_in[rname]:
                        a_to_in[rname].append(rdata)
                    if not rname in in_to_a[rdata]:
                        in_to_a[rdata].append(rname)

                elif t in ['CNAME',]:
                    rdata = to_str(a['rdata'])
                    rname = to_str(a['rrname'])
                    if not rname in cnames:
                        cnames[rname] = []

                    if not rdata in cnames[rname]:
                        cnames[rname].append(rdata)
                
                elif t in ['SRV',]:
                    rdata = to_str(a['target'])
                    rname = to_str(a['rrname'])
                    if not rname in cnames:
                        cnames[rname] = []

                    if not rdata in cnames[rname]:
                        cnames[rname].append(rdata)
        return {'unanswered': unanswered, 
                'ip_to_name': in_to_a,
                'name_to_ip': a_to_in,
                'cnames': cnames}

    @classmethod
    def get_resolutions(cls, resolutions):
        results = []
        resolved_names = lambda n, ips: ['%s ==> %s' % (n, ip) for ip in ips]
        for name, ips in resolutions.items(): 
            results = results + resolved_names(name, ips)
        return results

    @classmethod
    def print_resolutions(cls, resolutions):
        print ("Unanswered resolutions:\n%s"%('\n'.join(resolutions['unanswered'])))
        print ("Resolved hostnames:\n%s"%('\n'.join(cls.get_resolutions(resolutions['ip_to_name']))))
        print ("Resolved CNAMES:\n%s"%('\n'.join(cls.get_resolutions(resolutions['cnames']))))
