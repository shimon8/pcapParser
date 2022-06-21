from scapy.layers.dns import DNSQR
from scapy.utils import rdpcap
import re


def HTTPHeaders(http_payload):
        try:
            #isolate headers
            headers_raw = http_payload[:http_payload.index("\r\n\r\n") + 2]
            regex = r"(?P&lt;'name&gt;.*?): (?P&lt;value&gt;.*?)\r\n'"
            headers =  dict(re.findall(regex, headers_raw))
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
            text = http_payload[http_payload.index("\r\n\r\n")+4:]
            return text,text_type

def get_dns_query(pcap:rdpcap):
    return len([index for index, pkt in enumerate(pcap) if pkt.haslayer(DNSQR)])
def get_all_session(pcap:rdpcap):
    return len(pcap.sessions())
def get_packet_number(pcap):
    return len(pcap)

if __name__ == '__main__':
    pcap_path = r'C:\Users\shimo\OneDrive\Desktop\example.pcap'
    pcap_path = r'C:\Users\shimo\OneDrive\Desktop\ynet.pcap'

    pcap = rdpcap(pcap_path)
    print(get_all_session(pcap))
