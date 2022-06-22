import re
import zlib

from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP
from scapy.utils import rdpcap


class PcapParser:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.number_of_paket = 0
        self.number_of_sessions = 0
        self.all_dns_query = []
        self.http_flow = []

    def readPcap(self):
        pcap = rdpcap(self.pcap_path)
        self.number_of_paket = len(pcap)
        self.number_of_sessions = len(pcap.sessions())
        for line, pkt in enumerate(pcap):
            try:
                if pkt.haslayer(HTTPRequest):
                    self.read_http_request(pkt, pcap[line + 1:])
                elif pkt.haslayer(DNSQR):
                    self.all_dns_query.append(pkt)
            except Exception as error:
                print(error)
                continue

    def find_http_answer(self, cap: rdpcap, src_ip, src_port, dst_ip, dst_port):
        for pkt in cap:
            if not pkt.haslayer(HTTPResponse) or \
                    pkt.dst != src_ip or pkt.src != dst_ip or \
                    pkt.dport != src_port or pkt.sport != dst_port:
                continue
            return '\n'.join(str(pkt[TCP].payload).split('\\r\\n'))

    def read_http_request(self, pkt, pcap):
        src_ip = pkt.src
        dst_ip = pkt.dst
        src_port = pkt.sport
        dst_port = pkt.dport
        request_payload = '\n'.join(str(pkt[TCP].payload).split('\\r\\n'))
        answer_payload = self.find_http_answer(pcap, src_ip, src_port, dst_ip, dst_port)
        self.http_flow.append((request_payload, answer_payload))

    def print_http_flow(self):
        http_str = ''
        divider = f'{"-" * 30}\n'
        for http in self.http_flow:
            http_str += divider
            http_str += f'request: \n {http[0]}\n'
            http_str += f'response: \n {http[1]}\n'
            http_str += divider
        return http_str

    def __str__(self):
        return f'pcap path: {self.pcap_path}\n' \
               f'number of packets: {self.number_of_paket}\n' \
               f'number of Sessions: {self.number_of_sessions}\n' \
               f'number of DNS Query: {len(self.all_dns_query)}\n' \
               f'{"*" * 30} HTTP Flow {"*" * 30}\n' \
               f'{self.print_http_flow()}\n' \
               f'{"*" * 30} END HTTP Flow {"*" * 30}'
