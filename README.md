# ProtonVPN-IPs

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tn3w/ProtonVPN-IPs/main.yml?label=Build&style=for-the-badge)

An automatically updated list of IP addresses associated with the widely used free and privacy-focused VPN provider, ProtonVPN.

## Data Files

The script generates six data files:

1. `protonvpn_logicals.json` - Contains the raw response from ProtonVPN's API, including detailed information about all logical servers and their configurations.

2. `protonvpn_ips.json` - A JSON array containing only the unique exit IP addresses used by ProtonVPN servers. This is a simplified version of the data focusing only on the IP addresses.

3. `protonvpn_ips.txt` - A plain text file with one IP address per line, making it easy to use in scripts or other tools that expect a simple list format.

4. `protonvpn_subdomains.json` - A JSON array containing unique subdomains used by ProtonVPN servers.

5. `protonvpn_entry_ips.json` - A JSON array containing the unique entry IP addresses used by ProtonVPN servers.

6. `protonvpn_entry_ips.txt` - A plain text file with one IP address per line, making it easy to use in scripts or other tools that expect a simple list format.

## Token Authentication

The project uses Proton API authentication tokens to fetch VPN server data. It now supports automatic token refresh, which helps maintain uninterrupted access to the API even when tokens expire.

### Required Secrets

For GitHub Actions to work properly, set the following repository secrets:

- `AUTH_PM_UID`: Your Proton account UID (not changed by token refresh)
- `AUTH_TOKEN`: Initial authentication token
- `REFRESH_TOKEN`: Token used to refresh authentication credentials
- `SESSION_ID`: Your session ID
- `GH_TOKEN`: GitHub fine grained token with `Secrets: Read and Write` and `Contents: Read and Write` permissions used to update repository secrets

The workflow automatically refreshes tokens when needed and updates repository secrets accordingly.

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