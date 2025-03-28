import subprocess
import json
import os
import sys
import requests
from scapy.all import ARP, Ether, srp

def get_lan_ips():
    target_ip = input("Enter the target IP range (e.g., 192.168.1.1/24): ").strip() or '192.168.1.1/24'
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    try:
        result = srp(packet, timeout=3, verbose=0)[0]
    except Exception as e:
        print(f"Error during ARP scan: {e}")
        return []
    
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
    return devices

def ping_ip(ip):
    param = '-n' if os.name == 'nt' else '-c'
    try:
        result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True, check=True)
        return "TTL=" in result.stdout  # Check for TTL in response
    except subprocess.CalledProcessError:
        return False

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        response.raise_for_status()
        return response.json().get('ip', 'Unknown')
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return "Unknown"

def whois_lookup(ip):
    api_key = os.getenv('RAPIDAPI_KEY')
    if not api_key:
        print("Please set the RAPIDAPI_KEY environment variable.")
        return {}

    url = f'https://whois40.p.rapidapi.com/whois?q={ip}'
    headers = {
        'X-RapidAPI-Key': api_key,
        'X-RapidAPI-Host': "whois40.p.rapidapi.com"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching WHOIS data: {e}")
        return {}

def display_info():
    print("Fetching LAN IPs...")
    lan_devices = get_lan_ips()
    if not lan_devices:
        print("No devices found or error in scanning.")
    else:
        for device in lan_devices:
            is_active = ping_ip(device['ip'])
            print(f"IP: {device['ip']}, MAC: {device['mac']}, Active: {is_active}")
    
    print("\nFetching WAN IP...")
    wan_ip = get_public_ip()
    print(f"WAN IP: {wan_ip}")
    
    if wan_ip != "Unknown":
        print("Fetching WHOIS information...")
        whois_info = whois_lookup(wan_ip)
        print(json.dumps(whois_info, indent=4))

if __name__ == '__main__':
    display_info()
