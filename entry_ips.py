#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import time
import urllib.request
import urllib.error
import concurrent.futures
from typing import List, Set
import dns.resolver
import netaddr


TXT_HEADER = """#
# protonvpn_entry_ips.txt
# https://github.com/tn3w/ProtonVPN-IPs/blob/master/protonvpn_entry_ips.txt
#
# An automatically updated list of Entry IPs associated with the
# widely used free and privacy-focused VPN provider, ProtonVPN.
#
# This list could be used to block access to ProtonVPN's services.
#
"""


def get_ip_addresses(hostname: str) -> List[str]:
    """Get both IPv4 and IPv6 addresses for a hostname."""
    ip_addresses = []

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
        for addr in addrinfo:
            ip = addr[4][0]
            if ip not in ip_addresses:
                ip_addresses.append(ip)
    except (socket.gaierror, socket.herror):
        pass

    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(hostname, "A")
        for rdata in answers:
            ip = str(rdata)
            if ip not in ip_addresses:
                ip_addresses.append(ip)
    except Exception as e:
        print(f"Failed to resolve A record for {hostname}: {e}")

    try:
        answers = resolver.resolve(hostname, "AAAA")
        for rdata in answers:
            ip = str(rdata)
            if ip not in ip_addresses:
                ip_addresses.append(ip)
    except Exception as e:
        print(f"Failed to resolve AAAA record for {hostname}: {e}")

    return ip_addresses


def process_crtsh_subdomains(data: bytes, domain: str) -> Set[str]:
    """Process subdomains from crt.sh."""
    subdomains = set()
    data = json.loads(data.decode("utf-8"))
    print(f"Retrieved {len(data)} certificate records")

    for item in data:
        name_value = item.get("name_value", "")
        for name in name_value.split("\n"):
            if domain in name:
                name = name.strip().lower()
                if name.endswith(domain) and name != domain and "*" not in name:
                    subdomains.add(name)

    return subdomains


def get_subdomains_from_crtsh(domain: str) -> Set[str]:
    """Get subdomains for a domain from crt.sh using their web API."""
    subdomains = set()

    print(f"Finding subdomains for {domain} using crt.sh...")

    try:
        url = f"https://crt.sh/json?q={domain}"
        req = urllib.request.Request(url)

        with urllib.request.urlopen(req, timeout=60) as response:
            if response.status == 200:
                try:
                    subdomains = process_crtsh_subdomains(response.read(), domain)

                    print(f"Found {len(subdomains)} unique subdomains")
                except json.JSONDecodeError:
                    print("Failed to decode JSON response from crt.sh")
            else:
                print(f"Failed to query crt.sh API: HTTP {response.status}")
    except urllib.error.URLError as e:
        print(f"Error with crt.sh API: {e}")
    except Exception as e:
        print(f"Error with crt.sh API: {e}")

    return subdomains


def format_ip_addresses(ip_list: List[str]) -> List[str]:
    """Reorder the IP list to put IPv4 addresses first and expand IPv6 to long format."""
    ipv4_addresses = [ip for ip in ip_list if ":" not in ip]
    ipv6_addresses = []

    for ip in ip_list:
        if ":" in ip:
            try:
                ipv6_obj = netaddr.IPAddress(ip)
                if ipv6_obj.version == 6:
                    expanded_ip = str(ipv6_obj.format(netaddr.ipv6_verbose))
                    ipv6_addresses.append(expanded_ip)
                else:
                    ipv6_addresses.append(ip)
            except Exception:
                ipv6_addresses.append(ip)

    return ipv4_addresses + ipv6_addresses


def main():
    """Main function to discover subdomains and their IP addresses."""
    print("Starting Entry IP discovery...")
    base_domain = "protonvpn.net"
    all_ip_addresses = set()

    for i in range(10):
        subdomains = get_subdomains_from_crtsh(base_domain)
        if subdomains:
            break
        print(f"Attempt {i + 1}/10: No subdomains found from crt.sh API")
        print("Retrying in 30 seconds due to known intermittent issues...")
        time.sleep(30)

    if not subdomains:
        print("Error: No subdomains found. Exiting.")
        return

    with open("protonvpn_subdomains.json", "w", encoding="utf-8") as f:
        json.dump(list(subdomains), f, indent=2)

    print(f"Processing {len(subdomains)} subdomains...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_hostname = {
            executor.submit(get_ip_addresses, hostname): hostname
            for hostname in subdomains
        }

        for i, future in enumerate(concurrent.futures.as_completed(future_to_hostname)):
            hostname = future_to_hostname[future]
            try:
                ips = future.result()
                if ips:
                    print(f"Found {len(ips)} IPs for {hostname}")
                    all_ip_addresses.update(ips)
            except Exception as e:
                print(f"Error with {hostname}: {e}")

            if (i + 1) % 10 == 0:
                print(f"Progress: {i + 1}/{len(subdomains)} subdomains processed")

    unique_ips = list(all_ip_addresses)
    prioritized_ips = format_ip_addresses(unique_ips)

    with open("protonvpn_entry_ips.json", "w", encoding="utf-8") as f:
        json.dump(prioritized_ips, f, indent=2)

    with open("protonvpn_entry_ips.txt", "w", encoding="utf-8") as f:
        f.write(TXT_HEADER)
        f.write("\n".join(prioritized_ips))

    print("\nSummary:")
    print(f"Total subdomains discovered: {len(subdomains)}")
    print(f"Total unique Entry IPs found: {len(prioritized_ips)}")
    print(f"Entry IPv6 addresses: {sum(1 for ip in prioritized_ips if ':' in ip)}")
    print(f"Entry IPv4 addresses: {sum(1 for ip in prioritized_ips if ':' not in ip)}")
    print("Results saved to protonvpn_entry_ips.json and protonvpn_subdomains.json")


if __name__ == "__main__":
    main()
