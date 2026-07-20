#!/usr/bin/env python3
import ipaddress
import json
import mmap
import os
import socket
import struct
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
# ProtonVPN entry IPs, derived via the ASNDB database.
#
# ASNs that are shared consumer ISPs or CDNs are trimmed to only the ranges
# directly containing an entry IP, to avoid blocking unrelated services.
# All other ASNs are expanded to every range they announce.
#
# This list could be used to block access to ProtonVPN's services.
#
"""

BASE_DOMAIN = "protonvpn.net"

DB_URL = "https://github.com/tn3w/ASNDB/releases/latest/download/asndb-tiny.bin"
DB_PATH = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
DB_PATH = DB_PATH / "asndb" / "asndb-tiny.bin"

RANGES_OUTPUT = Path("protonvpn_entry_ip_ranges.txt")

SENSITIVE_ASNS = {
    6730: "Sunrise GmbH (Swiss consumer ISP)",
    8473: "Bahnhof AB (Swedish ISP)",
    35432: "Cablenet (Cyprus consumer ISP)",
    212238: "Datacamp / CDNEXT (CDN)",
    60068: "Datacamp / CDN77 (CDN)",
}

MAGIC = 0x000442444E534144
NO_ASN = 0xFFFFFFFF
V4_MAX = 0xFFFFFFFF
V6_MAX = (1 << 128) - 1

HDR = struct.Struct("<Q B 7x 6I 8Q")
TINY = struct.Struct("<IIII 2s 3B 3x")
U32 = struct.Struct("<I")
SEG4 = struct.Struct("<II")
SEG6 = struct.Struct("<16sI")


def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/json?q={domain}"
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
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

    return sorted(ip_addresses, key=ipaddress.ip_address)


class AsnDb:
    def __init__(self, path):
        self.file = open(path, "rb")
        self.mm = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        head = HDR.unpack_from(self.mm, 0)
        if head[0] != MAGIC:
            raise ValueError("bad magic")
        self.counts = dict(zip(("asn", "seg4", "seg6"), head[2:5]))
        self.asn_off = head[8]
        self.seg4_off, self.seg6_off = head[9], head[10]
        self.str_off = head[14]

    def asn_at(self, index):
        return U32.unpack_from(self.mm, self.asn_off + index * TINY.size)[0]

    def name_at(self, index):
        name_off = TINY.unpack_from(self.mm, self.asn_off + index * TINY.size)[1]
        if name_off == 0:
            return ""
        base = self.str_off + name_off
        (length,) = U32.unpack_from(self.mm, base)
        return self.mm[base + 4 : base + 4 + length].decode("utf-8", "replace")

    def locate(self, ip):
        address = ipaddress.ip_address(ip)
        if address.version == 4:
            return self._segment(
                self.seg4_off, self.counts["seg4"], 8, int(address),
                lambda offset: U32.unpack_from(self.mm, offset)[0], V4_MAX, 4,
            )
        return self._segment(
            self.seg6_off, self.counts["seg6"], 20, int(address),
            lambda offset: int.from_bytes(self.mm[offset : offset + 16], "big"),
            V6_MAX, 6,
        )

    def _segment(self, base, count, stride, key, key_at, top, version):
        lo, hi = 0, count
        while lo < hi:
            mid = (lo + hi) >> 1
            if key_at(base + mid * stride) <= key:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None

        record = base + (lo - 1) * stride
        index = U32.unpack_from(self.mm, record + stride - 4)[0]
        if index == NO_ASN:
            return None

        end = key_at(base + lo * stride) - 1 if lo < count else top
        return version, key_at(record), end, index

    def ranges_for(self, targets):
        return self._scan(
            self.seg4_off, self.counts["seg4"], SEG4, V4_MAX, 4, targets, int
        ) + self._scan(
            self.seg6_off, self.counts["seg6"], SEG6, V6_MAX, 6, targets,
            lambda raw: int.from_bytes(raw, "big"),
        )

    def _scan(self, base, count, fmt, top, version, targets, to_int):
        raw = self.mm[base : base + count * fmt.size]
        records = list(fmt.iter_unpack(raw))
        rows = []
        for index, (start, asn_index) in enumerate(records):
            if asn_index not in targets:
                continue
            end = to_int(records[index + 1][0]) - 1 if index + 1 < count else top
            rows.append((
                version, to_int(start), end,
                self.asn_at(asn_index), self.name_at(asn_index),
            ))
        return rows


def ensure_db(path, url):
    if path.exists():
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    urllib.request.urlretrieve(url, path)


def to_cidrs(version, start, end):
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return ipaddress.summarize_address_range(address(start), address(end))


def build_ranges(db, ip_addresses):
    targets = set()
    hits = {}
    unresolved = []
    for ip in ip_addresses:
        located = db.locate(ip)
        if located is None:
            unresolved.append(ip)
            continue

        version, start, end, index = located
        targets.add(index)
        hits[(version, start, end)] = index

    sensitive = {index for index in targets if db.asn_at(index) in SENSITIVE_ASNS}
    rows = db.ranges_for(targets - sensitive)
    for (version, start, end), index in hits.items():
        if index in sensitive:
            rows.append((version, start, end, db.asn_at(index), db.name_at(index)))

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
    rows, unresolved = build_ranges(AsnDb(DB_PATH), ip_addresses)
    write_ranges_txt(rows, RANGES_OUTPUT)

    asns = {asn for _, _, _, asn, _ in rows}
    print(f"Wrote {len(rows)} ranges across {len(asns)} ASNs")
    print(f"  trimmed to containing segments: {len(SENSITIVE_ASNS)} sensitive ASNs")
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
