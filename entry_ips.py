import json
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List


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


def get_subdomains_from_crtsh(domain: str) -> List[str]:
    """Get subdomains for a domain from crt.sh using their web API."""
    subdomains = set()
    try:
        with urllib.request.urlopen(
            f"https://crt.sh/json?q={domain}", timeout=60
        ) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                for item in data:
                    for name in item.get("name_value", "").split("\n"):
                        if (
                            domain in name
                            and name.endswith(domain)
                            and name != domain
                            and "*" not in name
                        ):
                            subdomains.add(name.strip().lower())
    except Exception as e:
        print(f"Error with crt.sh API: {e}")

    return list(subdomains)


def get_ips_for_hostname(hostname: str) -> List[str]:
    """Get both IPv4 and IPv6 addresses for a hostname."""
    ips = set()

    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except (socket.gaierror, socket.herror) as e:
        print(f"IPv4 lookup failed for {hostname}: {e}")

    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
            ips.add(info[4][0])
    except (socket.gaierror, socket.herror) as e:
        print(f"IPv6 lookup failed for {hostname}: {e}")

    return list(ips)


def batch_get_ips_for_hostnames(hostnames: List[str], workers: int = 10) -> List[str]:
    """Get IP addresses for multiple hostnames in parallel."""
    ip_addresses = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(get_ips_for_hostname, hostname): hostname
            for hostname in hostnames
        }

        for i, future in enumerate(as_completed(futures)):
            hostname = futures[future]
            try:
                ips = future.result()
                if ips:
                    print(f"Found {len(ips)} IPs for {hostname}")
                    ip_addresses.update(ips)
            except Exception as e:
                print(f"Error processing {hostname}: {e}")

            if (i + 1) % 10 == 0:
                print(f"Progress: {i + 1}/{len(hostnames)} hostnames processed")

    return list(ip_addresses)


def main():
    """Main function to discover subdomains and their IP addresses."""
    print("Starting Entry IP discovery...")
    base_domain = "protonvpn.net"

    subdomains = list()
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

    ip_addresses = batch_get_ips_for_hostnames(subdomains)
    with open("protonvpn_entry_ips.json", "w", encoding="utf-8") as f:
        json.dump(ip_addresses, f, indent=2)

    with open("protonvpn_entry_ips.txt", "w", encoding="utf-8") as f:
        f.write(TXT_HEADER)
        f.write("\n".join(ip_addresses))

    print("\nSummary:")
    print(f"Total subdomains discovered: {len(subdomains)}")
    print(f"Total unique Entry IPs found: {len(ip_addresses)}")
    print(f"Entry IPv6 addresses: {sum(1 for ip in ip_addresses if ':' in ip)}")
    print(f"Entry IPv4 addresses: {sum(1 for ip in ip_addresses if ':' not in ip)}")
    print("Results saved to protonvpn_entry_ips.json and protonvpn_subdomains.json")


if __name__ == "__main__":
    main()
