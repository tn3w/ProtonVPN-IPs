import ipaddress
import json
import mmap
import os
import socket
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
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


class AsnDb:
    """ASNDB tiny reader: mmap + struct + bisect over IP segments."""

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
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return self._segment(self.seg4_off, self.counts["seg4"], 8, int(addr),
                lambda o: U32.unpack_from(self.mm, o)[0], V4_MAX, 4)
        return self._segment(self.seg6_off, self.counts["seg6"], 20, int(addr),
            lambda o: int.from_bytes(self.mm[o : o + 16], "big"), V6_MAX, 6)

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
        start = key_at(record)
        end = key_at(base + lo * stride) - 1 if lo < count else top
        return version, start, end, index

    def ranges_for(self, targets):
        return self._scan(self.seg4_off, self.counts["seg4"], SEG4, V4_MAX, 4,
            targets, int) + self._scan(self.seg6_off, self.counts["seg6"], SEG6,
            V6_MAX, 6, targets, lambda b: int.from_bytes(b, "big"))

    def _scan(self, base, count, fmt, top, version, targets, to_int):
        raw = self.mm[base : base + count * fmt.size]
        records = list(fmt.iter_unpack(raw))
        out = []
        for i, (start, index) in enumerate(records):
            if index not in targets:
                continue
            end = to_int(records[i + 1][0]) - 1 if i + 1 < count else top
            out.append((version, to_int(start), end,
                self.asn_at(index), self.name_at(index)))
        return out


def ensure_db(path, url):
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    urllib.request.urlretrieve(url, path)


def to_cidrs(version, start, end):
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return ipaddress.summarize_address_range(cls(start), cls(end))


def build_ranges(db, ip_addresses):
    """Resolve IPs to ASN ranges: full ASN expansion, sensitive ASNs trimmed."""
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

    sensitive = {i for i in targets if db.asn_at(i) in SENSITIVE_ASNS}
    rows = db.ranges_for(targets - sensitive)
    for (version, start, end), index in hits.items():
        if index in sensitive:
            rows.append((version, start, end, db.asn_at(index), db.name_at(index)))

    return sorted(set(rows)), unresolved


def write_ranges_txt(rows, path):
    lines = []
    for version, start, end, _, _ in rows:
        lines.extend(str(net) for net in to_cidrs(version, start, end))
    with path.open("w", encoding="utf-8") as f:
        f.write(RANGES_HEADER)
        f.write("\n".join(lines))


def generate_ranges(ip_addresses):
    ensure_db(DB_PATH, DB_URL)
    db = AsnDb(DB_PATH)
    rows, unresolved = build_ranges(db, ip_addresses)
    write_ranges_txt(rows, RANGES_OUTPUT)
    asns = {asn for _, _, _, asn, _ in rows}
    print(f"Wrote {len(rows)} ranges across {len(asns)} ASNs")
    print(f"  trimmed to containing segments: {len(SENSITIVE_ASNS)} sensitive ASNs")
    if unresolved:
        print(f"  unresolved IPs: {len(unresolved)}")


def main():
    """Discover ProtonVPN entry IPs and build the ASN range blocklist."""
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

    ipv4_count = sum(1 for ip in ip_addresses if ":" not in ip)
    ipv6_count = sum(1 for ip in ip_addresses if ":" in ip)
    total = len(ip_addresses)

    print("\nSummary:")
    print(f"Total subdomains discovered: {len(subdomains)}")
    print(f"Total unique Entry IPs found: {total}")

    print("\nIP Address Distribution:")
    ipv4_bar = "█" * int(30 * ipv4_count / total)
    ipv6_bar = "█" * int(30 * ipv6_count / total)

    print(f"IPv4 ({ipv4_count}): {ipv4_bar} {ipv4_count/total:.1%}")
    print(f"IPv6 ({ipv6_count}): {ipv6_bar} {ipv6_count/total:.1%}")

    print("\nGenerating ASN range blocklist...")
    generate_ranges(ip_addresses)


if __name__ == "__main__":
    main()
