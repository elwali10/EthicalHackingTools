#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface", help="interface to change its MAC Address")
    parser.add_option("-m","--newMAC",dest="new_mac", help="new mac address")
    (options,arguments)= parser.parse_args()
    if not options.interface:
        parser.error(" [-] Please specify an interface, or use --help for more info")
    if not options.new_mac:
        parser.error(" [-] Please specify a new mac, or use --help for more info ")
    return options

def change_mac(interface,mac):  
    print ("[+] Changing address mac for " + interface + " to " + mac)
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",mac])
    subprocess.call(["ifconfig",interface,"up"])

def get_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig",interface])
    print ifconfig_result
    mac_address_search_result = re.search(r"\w+\w+:\w+\w+:\w+\w+:\w+\w+:\w+\w+:\w+\w+", ifconfig_result)
    if mac_address_search_result :
        print mac_address_search_result.group(0)
    else : 
        print ("[-] could not read mac address")

options=get_arguments()
current_mac = get_mac(options.interface)
print current_mac
change_mac(options.interface,options.new_mac)
new_mac = get_mac(options.interface)
print new_mac

#subprocess.call("ifconfig "+interface+" down",shell=True)
#subprocess.call("ifconfig "+interface+" hw ether "+ new_mac,shell=True)
#subprocess.call("ifconfig "+interface+" up",shell=True)
#subprocess.call(["ifconfig",interface,"down"])
#subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
#subprocess.call(["ifconfig",interface,"up"])
