<div align="center">
  
# ProtonVPN-IPs

An automatically updated list of IP addresses associated with the widely used free and privacy-focused VPN provider, ProtonVPN.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tn3w/ProtonVPN-IPs/main.yml?label=Build&style=for-the-badge)

### IPInfo Category

[IPSet](https://github.com/tn3w/IPSet) | [ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) | [TunnelBear-IPs](https://github.com/tn3w/TunnelBear-IPs)

</div>

## Table of Contents

- [Data Files](#data-files)
- [Token Authentication](#token-authentication)
- [Usage Examples](#usage-examples)
- [License](#license)

## Data Files

| File                        | Raw Link                                                                                                | Purpose                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `protonvpn_logicals.json`   | [Raw](https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_logicals.json)   | Complete ProtonVPN API response with detailed server configurations |
| `protonvpn_ips.json`        | [Raw](https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_ips.json)        | Unique exit IP addresses (JSON array)                               |
| `protonvpn_ips.txt`         | [Raw](https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_ips.txt)         | Unique exit IP addresses (plain text, one per line)                 |
| `protonvpn_entry_ips.json`  | [Raw](https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_entry_ips.json)  | Unique entry IP addresses (JSON array)                              |
| `protonvpn_entry_ips.txt`   | [Raw](https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_entry_ips.txt)   | Unique entry IP addresses (plain text, one per line)                |
| `protonvpn_subdomains.json` | [Raw](https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_subdomains.json) | Unique ProtonVPN subdomains                                         |

## Token Authentication

The project uses Proton API authentication tokens with automatic refresh capability. The workflow automatically updates expired tokens.

### Required Repository Secrets

| Secret          | Source                           | Purpose                   |
| --------------- | -------------------------------- | ------------------------- |
| `AUTH_PM_UID`   | ProtonVPN cookie `AUTH-{uid}`    | Account identifier        |
| `AUTH_TOKEN`    | ProtonVPN cookie value           | Authentication token      |
| `REFRESH_TOKEN` | ProtonVPN cookie `REFRESH-{uid}` | Token refresh credentials |
| `SESSION_ID`    | ProtonVPN cookie `Session-Id`    | Session identifier        |
| `GH_TOKEN`      | GitHub fine-grained token        | Update repository secrets |

### Quick Setup

1. **Extract ProtonVPN tokens**: Login to [account.protonvpn.com](https://account.protonvpn.com), open browser dev tools (F12), go to Web Storage → Cookies, extract cookie values
2. **Create GitHub token**: Go to GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens, create with `Contents: Read/Write` and `Secrets: Read/Write` permissions
3. **Add secrets**: In your repository, go to Settings → Secrets and variables → Actions, add all required secrets
4. **Test**: Run the workflow from Actions tab

### Token Details

From your browser's Web Storage → Cookies, extract:

- **AUTH_PM_UID**: The `{uid}` from `AUTH-{uid}` cookie name
- **AUTH_TOKEN**: Value of `AUTH-{uid}` cookie
- **REFRESH_TOKEN**: Value of `REFRESH-{uid}` cookie
- **SESSION_ID**: Value of `Session-Id` cookie

### Notes

- Tokens refresh automatically every ~24 hours
- `REFRESH_TOKEN` expires after ~180 days (manual renewal required)
- Free accounts access fewer servers than paid accounts
- Never share tokens publicly

## Usage Examples

### Check Exit IP

```python
import json
import netaddr

def is_protonvpn_exit_ip(ip_to_check):
    try:
        netaddr.IPAddress(ip_to_check)
        with open('protonvpn_ips.json', 'r') as f:
            protonvpn_ips = json.load(f)
        return ip_to_check in protonvpn_ips
    except:
        return False

# Usage
if is_protonvpn_exit_ip("84.247.50.181"):
    print("ProtonVPN exit IP detected")
```

### Check Entry IP

```python
import json
import netaddr

def is_protonvpn_entry_ip(ip_to_check):
    try:
        netaddr.IPAddress(ip_to_check)
        with open('protonvpn_entry_ips.json', 'r') as f:
            protonvpn_ips = json.load(f)
        return ip_to_check in protonvpn_ips
    except:
        return False

# Usage
if is_protonvpn_entry_ip("146.70.120.210"):
    print("ProtonVPN entry IP detected")
```

### Bulk IP Check

```python
import json
from typing import List, Dict

def check_multiple_ips(ips_to_check: List[str]) -> Dict[str, Dict[str, bool]]:
    try:
        with open('protonvpn_ips.json', 'r') as f:
            exit_ips = set(json.load(f))
        with open('protonvpn_entry_ips.json', 'r') as f:
            entry_ips = set(json.load(f))

        results = {}
        for ip in ips_to_check:
            results[ip] = {
                'is_exit_ip': ip in exit_ips,
                'is_entry_ip': ip in entry_ips
            }
        return results
    except Exception as e:
        return {'error': str(e)}

# Usage
ips = ["146.70.120.210", "84.247.50.181", "192.168.1.1"]
results = check_multiple_ips(ips)
for ip, status in results.items():
    print(f"{ip}: Exit={status.get('is_exit_ip', False)}, Entry={status.get('is_entry_ip', False)}")
```

## License

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
