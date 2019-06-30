#!/usr/bin/env python

import scapy.all as scapy
import optparse



def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="ip",help="IP target to be scanned")
    (options,arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an IP or IP ranger to be scanned, use --help for more info")
    return options    


def scan(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    #print(arp_request.summary())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    #print(broadcast.summary())
    arp_request_broadcast = broadcast/arp_request
    #arp_request_broadcast.show()
    #print(arp_request_broadcast.summary())
    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    #print answered_list.summary()
    #scapy.ls(scapy.Ether())
    clients_list = []
    #print("IP\t\t\tMAC ADDRESS\n-----------------------------------")
    for element in answered_list :
        client_dict = {"ip": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)
        #print (element[1].psrc+"\t\t"+ element[1].hwsrc)
        #print ("---------------------------------------")
    return clients_list    

def print_result(clients_list):
    print("IP\t\t\tMAC ADDRESS\n-----------------------------------")
    for client in clients_list :
        print (client["ip"] +"\t\t"+client["MAC"])



options=get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)



