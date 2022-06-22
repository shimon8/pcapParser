from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPResponse, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap
import re

from PcapParser import PcapParser


def HTTPHeaders(http_payload):
    try:
        # isolate headers
        headers_raw = http_payload[:http_payload.index("\r\n\r\n") + 2]
        regex = r"(?P&lt;'name&gt;.*?): (?P&lt;value&gt;.*?)\r\n'"
        headers = dict(re.findall(regex, headers_raw))
    except:
        return None
    if 'Content-Type' not in headers:
        return None
    return headers


def extractText(headers, http_payload):
    text = None
    text_type = None
    if 'text' in headers['Content-Type']:
        text_type = headers['Content-Type'].split("/")[1]
        text = http_payload[http_payload.index("\r\n\r\n") + 4:]
        return text, text_type


def get_dns_query(pcap: rdpcap):
    return len([index for index, pkt in enumerate(pcap) if pkt.haslayer(DNSQR)])


def get_all_session(pcap1: rdpcap):
    return len(pcap1.sessions())


def get_packet_number(pcap):
    return len(pcap)


def find_answer(cap: rdpcap, src_ip, src_port, dst_ip, dst_port):
    for pkt in cap:
        if not pkt.haslayer(HTTPResponse) or \
                pkt.dst != src_ip or pkt.src != dst_ip or \
                pkt.dport != src_port or pkt.sport != dst_port:
            continue
        return str(pkt['TCP'].payload)


def get_http_flow(pcap: rdpcap):
    http_flow = []
    for line, pkt in enumerate(pcap):
        if pkt.haslayer(HTTPRequest):
            try:
                src_ip = pkt.src
                dst_ip = pkt.dst
                src_port = pkt.sport
                dst_port = pkt.dport
                request_payload = str(pkt.payload)
                answer_payload = find_answer(pcap[line + 1:], src_ip, src_port, dst_ip, dst_port)
                http_flow.append((request_payload, answer_payload))
            except:
                print(pkt)
                continue

if __name__ == '__main__':
    pcap_path = r'C:\Users\shimo\OneDrive\Desktop\example.pcap'
    #pcap_path = r'C:\Users\shimo\OneDrive\Desktop\ynet.pcap'

    pcap = PcapParser(pcap_path)
    pcap1=rdpcap(pcap_path)
    pcap.readPcap()
    print(pcap)
    #print(pcap.http_flow)
    # print(len(pcap.all_dns_query))
    # print(get_dns_query(pcap1))
    # print('*'*60)
    # print(get_all_session(pcap1))
    # print(pcap.number_of_sessions)
    #print(get_http_flow(pcap))