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

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# Ping an IP to see if it is active
def ping_ip(ip):
    try:
        # Use 'ping -n 1' for Windows, '-c 1' for Linux/Unix
        param = '-n' if os.name == 'nt' else '-c'
        output = subprocess.check_output(f"ping {param} 1 {ip}", shell=True)
        return True
    except subprocess.CalledProcessError:
        return False
    
# Get public IP (WAN)
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        return response.json()['ip']
    except Exception as e:
        return str(e)
    
# WHOIS Lookup for WAN IP using python-whois package
def whois_lookup(ip):
    try:
        w = whois.whois(ip)
        return w  # Return WHOIS data
    except Exception as e:
        return str(e)
    
