import errno
import os
import sys
from PcapParser import PcapParser



if __name__ == '__main__':
    print(len(sys.argv))
    if len(sys.argv) != 2:
        raise Exception('ERROR: Missing pcap path. ')
    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), pcap_path)

    pcap = PcapParser(pcap_path)
    pcap.readPcap()
    print(pcap)
