import subprocess
import json
from scapy.all import ARP, Ether, srp
import requests
import os
import whois

# Get LAN IPs
def get_lan_ips():
    target_ip = input("Enter the target IP range (e.g.,192.168.1.1/24): ")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    