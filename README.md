<div align="center">
  
# ProtonVPN-IPs

🔒 An automatically updated list of IP addresses associated with the widely used free and privacy-focused VPN provider, ProtonVPN.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tn3w/ProtonVPN-IPs/main.yml?label=Build&style=for-the-badge)

### IPInfo Category
[IPSet](https://github.com/tn3w/IPSet) | [ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) | [Tunnelbear-IPs](https://github.com/tn3w/Tunnelbear-IPs)

</div>

## 📊 Data Files

The repository maintains six regularly updated data files:

1. `protonvpn_logicals.json` - Contains the raw response from ProtonVPN's API, including detailed information about all logical servers and their configurations.

2. `protonvpn_ips.json` - A JSON array containing only the unique exit IP addresses used by ProtonVPN servers. This is a simplified version of the data focusing only on the IP addresses.

3. `protonvpn_ips.txt` - A plain text file with one IP address per line, making it easy to use in scripts or other tools that expect a simple list format.

4. `protonvpn_subdomains.json` - A JSON array containing unique subdomains used by ProtonVPN servers.

5. `protonvpn_entry_ips.json` - A JSON array containing the unique entry IP addresses used by ProtonVPN servers.

6. `protonvpn_entry_ips.txt` - A plain text file with one IP address per line, making it easy to use in scripts or other tools that expect a simple list format.

## 🛠️ Usage Examples

### Checking if an IP address is a ProtonVPN IP

#### Python Example - Check Exit IP

```python
import json
import netaddr

def is_protonvpn_exit_ip(ip_to_check, json_path='protonvpn_ips.json'):
    """Check if an IP address is a ProtonVPN exit IP"""
    try:
        # Validate IP address format
        netaddr.IPAddress(ip_to_check)
        
        # Load the ProtonVPN IPs list
        with open(json_path, 'r') as f:
            protonvpn_ips = json.load(f)
            
        # Check if IP is in the list
        return ip_to_check in protonvpn_ips
    except netaddr.AddrFormatError:
        print(f"Error: {ip_to_check} is not a valid IP address")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# Usage example
ip = "84.247.50.181"  # Example IP address
if is_protonvpn_exit_ip(ip):
    print(f"{ip} is a ProtonVPN exit IP")
else:
    print(f"{ip} is not a ProtonVPN exit IP")
```

#### Python Example - Check Entry IP

```python
import json
import netaddr

def is_protonvpn_entry_ip(ip_to_check, json_path='protonvpn_entry_ips.json'):
    """Check if an IP address is a ProtonVPN entry IP"""
    try:
        # Validate IP address format
        netaddr.IPAddress(ip_to_check)
        
        # Load the ProtonVPN IPs list
        with open(json_path, 'r') as f:
            protonvpn_ips = json.load(f)
            
        # Check if IP is in the list
        return ip_to_check in protonvpn_ips
    except netaddr.AddrFormatError:
        print(f"Error: {ip_to_check} is not a valid IP address")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# Usage example
ip = "146.70.120.210"  # Example IP address
if is_protonvpn_entry_ip(ip):
    print(f"{ip} is a ProtonVPN entry IP")
else:
    print(f"{ip} is not a ProtonVPN entry IP")
```

#### Bulk IP Checking (Python)

```python
import json
import netaddr
from typing import List, Dict

def check_multiple_ips(ips_to_check: List[str]) -> Dict[str, Dict[str, bool]]:
    """Check multiple IPs against both entry and exit IP lists"""
    # Load IP lists
    try:
        with open('protonvpn_ips.json', 'r') as f:
            exit_ips = set(json.load(f))
        
        with open('protonvpn_entry_ips.json', 'r') as f:
            entry_ips = set(json.load(f))
            
        # Check each IP
        results = {}
        for ip in ips_to_check:
            try:
                netaddr.IPAddress(ip)  # Validate IP format
                results[ip] = {
                    'is_exit_ip': ip in exit_ips,
                    'is_entry_ip': ip in entry_ips
                }
            except netaddr.AddrFormatError:
                results[ip] = {'error': f"Invalid IP address format"}
                
        return results
    
    except Exception as e:
        return {'error': str(e)}

# Example usage
ips = ["146.70.120.210", "84.247.50.181", "192.168.1.1"]
results = check_multiple_ips(ips)

for ip, status in results.items():
    print(f"IP: {ip}")
    if 'error' in status:
        print(f"  Error: {status['error']}")
    else:
        print(f"  ProtonVPN Exit IP: {'Yes' if status['is_exit_ip'] else 'No'}")
        print(f"  ProtonVPN Entry IP: {'Yes' if status['is_entry_ip'] else 'No'}")
```

## 🔄 Token Authentication

The project uses Proton API authentication tokens to fetch VPN server data. It now supports automatic token refresh, which helps maintain uninterrupted access to the API even when tokens expire.

### Required Secrets

For GitHub Actions to work properly, set the following repository secrets:

- `AUTH_PM_UID`: Your Proton account UID (not changed by token refresh)
- `AUTH_TOKEN`: Initial authentication token
- `REFRESH_TOKEN`: Token used to refresh authentication credentials
- `SESSION_ID`: Your session ID
- `GH_TOKEN`: GitHub fine grained token with `Secrets: Read and Write` and `Contents: Read and Write` permissions used to update repository secrets

The workflow automatically refreshes tokens when needed and updates repository secrets accordingly.

## 🔬 Technical Implementation

### Exit IP Discovery (`main.py`)

The exit IP discovery process implements authenticated API interaction with ProtonVPN's official endpoints:

1. **Authentication Flow**:
   - Implements cookie-based authentication using `AUTH-{uid}` and `Session-Id` tokens
   - Handles token refresh via `/api/auth/refresh` endpoint on token expiration
   - Extracts new tokens from HTTP response headers (`Set-Cookie`)

2. **API Integration**:
   - Fetches server data from `account.protonvpn.com/api/vpn/logicals` endpoint
   - Uses HTTP headers including `x-pm-appversion`, `x-pm-uid` for API versioning
   - Dynamically identifies latest app version from manifest.json

3. **Data Processing**:
   - Traverses the nested JSON structure (`LogicalServers[].Servers[].ExitIP`)
   - Performs deduplication using Python sets (`set()`)
   - Combines API data with local base data for enhanced coverage
   - Serializes to both JSON and plain text formats

### Entry IP Discovery (`entry_ips.py`)

The entry IP discovery process employs passive reconnaissance techniques:

1. **Subdomain Enumeration**:
   - Leverages Certificate Transparency logs via crt.sh API
   - Implements retry logic (10 attempts with 30s intervals) for API resilience
   - Filters and normalizes subdomains

2. **DNS Resolution**:
   - Uses socket library with specific address family parameters (AF_INET, AF_INET6)
   - Directly resolves both IPv4 (A records) and IPv6 (AAAA records)
   - Utilizes concurrent execution (`ThreadPoolExecutor`) for parallel DNS resolution

3. **IP Processing**:
   - Employs set data structures for efficient deduplication
   - Maintains mixed IPv4/IPv6 collections in output
   - Handles network errors gracefully with specific exception handling

## 📜 License
Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.