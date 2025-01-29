import sys
import requests
import dns.resolver
import socket
from scapy.all import ARP, Ether, srp
import pyfiglet

def print_banner():
    banner = pyfiglet.figlet_format("DeeSociety")
    print(banner)

def dns_lookup(domain):
    print(f"\nDNS Lookup for {domain}:")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for answer in answers:
            print(f"IP Address: {answer}")
    except Exception as e:
        print(f"Error: {e}")

def whois_lookup(domain):
    print(f"\nWHOIS Lookup for {domain}:")
    try:
        response = requests.get(f"https://whois.arin.net/rest/nets;q={domain}?showDetails=true&showARIN=false&ext=netref2")
        if response.status_code == 200:
            print(response.text)
        else:
            print("WHOIS information could not be retrieved.")
    except Exception as e:
        print(f"Error: {e}")

def ip_geolocation(ip):
    print(f"\nIP Geolocation for {ip}:")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            print(f"IP: {data['ip']}")
            print(f"City: {data['city']}")
            print(f"Region: {data['region']}")
            print(f"Country: {data['country']}")
            print(f"Location: {data['loc']}")
            print(f"Organization: {data['org']}")
        else:
            print("Geolocation information could not be retrieved.")
    except Exception as e:
        print(f"Error: {e}")

def network_scan(ip_range):
    print(f"\nScanning network: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Available devices in the network:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

def main():
    print_banner()
    
    while True:
        print("\nMenu:")
        print("1. DNS Lookup")
        print("2. WHOIS Lookup")
        print("3. IP Geolocation")
        print("4. Network Scan")
        print("5. Exit")
        
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            domain = input("Enter the domain name: ")
            dns_lookup(domain)
        elif choice == '2':
            domain = input("Enter the domain name: ")
            whois_lookup(domain)
        elif choice == '3':
            ip = input("Enter the IP address: ")
            try:
                socket.inet_aton(ip)  # Check if it's a valid IP address
                ip_geolocation(ip)
            except socket.error:
                print("Invalid IP address format.")
        elif choice == '4':
            ip_range = input("Enter the IP range (e.g., 192.168.1.1/24): ")
            network_scan(ip_range)
        elif choice == '5':
            print("Exiting the program.")
            sys.exit(0)
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()