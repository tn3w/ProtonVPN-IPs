#!/usr/bin/env python3
import bisect
import gzip
import ipaddress
import json
import os
import shutil
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


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

RANGES_HEADER = """#
# protonvpn_entry_ip_ranges.txt
# https://github.com/tn3w/ProtonVPN-IPs/blob/master/protonvpn_entry_ip_ranges.txt
#
# An automatically updated list of CIDR ranges of the ASNs that host
# ProtonVPN entry IPs, derived from the iptoasn.com database.
#
# ASNs that are shared consumer ISPs or CDNs are trimmed to only the ranges
# directly containing an entry IP, to avoid blocking unrelated services.
# All other ASNs are expanded to every range they announce.
#
# This list could be used to block access to ProtonVPN's services.
#
"""

BASE_DOMAIN = "protonvpn.net"

DB_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
DB_PATH = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
DB_PATH = DB_PATH / "ip2asn" / "ip2asn-combined.tsv.gz"
DB_MAX_AGE = 24 * 3600

VPN_LIST_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt"

RANGES_OUTPUT = Path("protonvpn_entry_ip_ranges.txt")

SENSITIVE_ASNS = {
    6730: "Sunrise GmbH (Swiss consumer ISP)",
    8473: "Bahnhof AB (Swedish ISP)",
    35432: "Cablenet (Cyprus consumer ISP)",
    212238: "Datacamp / CDNEXT (CDN)",
    60068: "Datacamp / CDN77 (CDN)",
}

USER_AGENT = (
    "ProtonVPN-IPs/1.0 (+https://github.com/tn3w/ProtonVPN-IPs)"
)


def open_url(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(request, timeout=timeout)


def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/json?q={domain}"
    try:
        with open_url(url) as response:
            if response.status != 200:
                return set()
            entries = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        print(f"Error with crt.sh API: {error}")
        return set()

    names = (
        name.strip().lower()
        for entry in entries
        for name in entry.get("name_value", "").split("\n")
    )

    return {
        name
        for name in names
        if name.endswith(domain) and name != domain and "*" not in name
    }


def fetch_subdomains(domain, attempts=10, delay=30):
    for attempt in range(1, attempts + 1):
        subdomains = get_subdomains_from_crtsh(domain)
        if subdomains:
            return sorted(subdomains)

        print(f"Attempt {attempt}/{attempts}: No subdomains found from crt.sh API")
        if attempt < attempts:
            print(f"Retrying in {delay} seconds due to known intermittent issues...")
            time.sleep(delay)

    return []


def ip_sort_key(ip):
    address = ipaddress.ip_address(ip)
    return address.version, address


def get_ips_for_hostname(hostname):
    ip_addresses = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(hostname, None, family)
        except (socket.gaierror, socket.herror, UnicodeError) as error:
            print(f"Lookup failed for {hostname}: {error}")
            continue

        ip_addresses.update(info[4][0] for info in infos)

    return ip_addresses


def resolve_hostnames(hostnames, workers=10):
    ip_addresses = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(get_ips_for_hostname, hostname): hostname
            for hostname in hostnames
        }

        for index, future in enumerate(as_completed(futures), 1):
            resolved = future.result()
            if resolved:
                print(f"Found {len(resolved)} IPs for {futures[future]}")
                ip_addresses.update(resolved)

            if index % 10 == 0:
                print(f"Progress: {index}/{len(hostnames)} hostnames processed")

    return sorted(ip_addresses, key=ip_sort_key)


class AsnTable:
    def __init__(self, path):
        self.rows = {4: [], 6: []}
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as file:
            for line in file:
                first, last, asn, _, name = line.rstrip("\n").split("\t")
                if asn == "0":
                    continue

                start = ipaddress.ip_address(first)
                end = ipaddress.ip_address(last)
                self.rows[start.version].append(
                    (int(start), int(end), int(asn), name)
                )

        for rows in self.rows.values():
            rows.sort()
        self.starts = {version: [row[0] for row in rows]
                       for version, rows in self.rows.items()}

    def locate(self, ip):
        address = ipaddress.ip_address(ip)
        rows = self.rows[address.version]
        index = bisect.bisect_right(self.starts[address.version], int(address)) - 1
        if index < 0:
            return None

        start, end, asn, name = rows[index]
        if int(address) > end:
            return None

        return address.version, start, end, asn, name

    def ranges_for(self, asns):
        return [
            (version, start, end, asn, name)
            for version, rows in self.rows.items()
            for start, end, asn, name in rows
            if asn in asns
        ]


class IntervalSet:
    def __init__(self, intervals):
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self.starts = [start for start, _ in merged]
        self.ends = [end for _, end in merged]

    def contains(self, start, end):
        index = bisect.bisect_right(self.starts, start) - 1
        return index >= 0 and end <= self.ends[index]


def fetch_vpn_ranges(url):
    print(f"Downloading {url}")
    try:
        with open_url(url) as response:
            text = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Error fetching VPN list: {error}")
        return IntervalSet([])

    intervals = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            start = int(network.network_address)
            intervals.append((start, int(network.broadcast_address)))

    return IntervalSet(intervals)


def ensure_db(path, url):
    if path.exists() and time.time() - path.stat().st_mtime < DB_MAX_AGE:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    with open_url(url) as response, path.open("wb") as file:
        shutil.copyfileobj(response, file)


def to_cidrs(version, start, end):
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return ipaddress.summarize_address_range(address(start), address(end))


def build_ranges(table, ip_addresses, vpn_ranges):
    targets = set()
    hits = set()
    unresolved = []
    for ip in ip_addresses:
        located = table.locate(ip)
        if located is None:
            unresolved.append(ip)
            continue

        targets.add(located[3])
        hits.add(located)

    rows = []
    for row in table.ranges_for(targets):
        version, start, end, asn, _ = row
        if asn not in SENSITIVE_ASNS:
            rows.append(row)
        elif version == 4 and vpn_ranges.contains(start, end):
            rows.append(row)

    rows.extend(row for row in hits if row[3] in SENSITIVE_ASNS)

    return sorted(set(rows)), unresolved


def write_ranges_txt(rows, path):
    lines = []
    for version, start, end, _, _ in rows:
        lines.extend(str(network) for network in to_cidrs(version, start, end))

    with path.open("w", encoding="utf-8") as file:
        file.write(RANGES_HEADER)
        file.write("\n".join(lines))


def generate_ranges(ip_addresses):
    ensure_db(DB_PATH, DB_URL)
    vpn_ranges = fetch_vpn_ranges(VPN_LIST_URL)
    rows, unresolved = build_ranges(AsnTable(DB_PATH), ip_addresses, vpn_ranges)
    write_ranges_txt(rows, RANGES_OUTPUT)

    asns = {asn for _, _, _, asn, _ in rows}
    print(f"Wrote {len(rows)} ranges across {len(asns)} ASNs")
    print(f"  {len(SENSITIVE_ASNS)} sensitive ASNs trimmed to VPN-list + entry ranges")
    if unresolved:
        print(f"  unresolved IPs: {len(unresolved)}")


def write_outputs(subdomains, ip_addresses):
    with open("protonvpn_subdomains.json", "w", encoding="utf-8") as file:
        json.dump(subdomains, file, indent=2)

    with open("protonvpn_entry_ips.json", "w", encoding="utf-8") as file:
        json.dump(ip_addresses, file, indent=2)

    with open("protonvpn_entry_ips.txt", "w", encoding="utf-8") as file:
        file.write(TXT_HEADER)
        file.write("\n".join(ip_addresses))


def print_distribution(ip_addresses):
    total = len(ip_addresses)
    if not total:
        return

    ipv4_count = sum(1 for ip in ip_addresses if ":" not in ip)
    counts = {"IPv4": ipv4_count, "IPv6": total - ipv4_count}

    print("\nIP Address Distribution:")
    for label, count in counts.items():
        bar = "█" * int(30 * count / total)
        print(f"{label} ({count}): {bar} {count / total:.1%}")


def main():
    print("Starting Entry IP discovery...")

    subdomains = fetch_subdomains(BASE_DOMAIN)
    if not subdomains:
        print("Error: No subdomains found. Exiting.")
        return

    print(f"Processing {len(subdomains)} subdomains...")
    ip_addresses = resolve_hostnames(subdomains)

    write_outputs(subdomains, ip_addresses)

    print("\nSummary:")
    print(f"Total subdomains discovered: {len(subdomains)}")
    print(f"Total unique Entry IPs found: {len(ip_addresses)}")

    print_distribution(ip_addresses)

    print("\nGenerating ASN range blocklist...")
    generate_ranges(ip_addresses)


if __name__ == "__main__":
    main()
