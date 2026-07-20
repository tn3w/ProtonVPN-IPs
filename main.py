#!/usr/bin/env python3
import http.client
import http.cookies
import ipaddress
import json
import os
import urllib.error
import urllib.request


TXT_HEADER = """#
# protonvpn_ips.txt
# https://github.com/tn3w/ProtonVPN-IPs/blob/master/protonvpn_ips.txt
#
# An automatically updated list of IP addresses associated with the
# widely used free and privacy-focused VPN provider, ProtonVPN.
#
# This list could be used to block malicious traffic from ProtonVPN's servers.
#
"""

VERSION_URL = "https://account.protonvpn.com/assets/yandex-browser-manifest.json"
BASE_LOGICALS_PATH = "dev_base.json"


class WebException(Exception):
    def __init__(self, message, status_code, reason):
        super().__init__(f"{message} Status: {status_code}, reason: {reason}")


def load_dotenv(path=".env"):
    if not os.path.exists(path):
        return

    with open(path, encoding="utf-8") as file:
        for line in file:
            key, separator, value = line.strip().partition("=")
            if separator and not key.startswith("#"):
                os.environ[key.strip()] = value.strip().strip("\"'")

    print(f"Loaded environment variables from {path}")


def get_latest_app_version():
    try:
        with urllib.request.urlopen(VERSION_URL) as response:
            return f"web-vpn-settings@{json.load(response)['version']}"
    except (urllib.error.URLError, KeyError):
        return None


def build_cookie_header(cookies):
    jar = http.cookies.SimpleCookie()
    for name, value in cookies.items():
        jar[name] = value

    return jar.output(attrs=[], header="", sep="; ")


def extract_cookie(headers, name):
    for header_name, value in headers:
        if header_name.lower() == "set-cookie" and value.startswith(f"{name}="):
            return value[len(name) + 1 :].split(";")[0]

    return None


def request_json(host, method, path, headers):
    connection = http.client.HTTPSConnection(host)
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    body = response.read().decode()
    response_headers = response.getheaders()
    connection.close()

    return response.status, response.reason, response_headers, body


def refresh_auth_token(auth_pm_uid, refresh_token, app_version):
    print("Refreshing authentication tokens...")

    headers = {
        "x-pm-appversion": app_version,
        "x-pm-uid": auth_pm_uid,
        "Cookie": build_cookie_header({f"REFRESH-{auth_pm_uid}": refresh_token}),
    }

    status, reason, response_headers, _ = request_json(
        "account.proton.me", "POST", "/api/auth/refresh", headers
    )
    if status != 200:
        raise WebException("Failed to refresh authentication tokens", status, reason)

    new_auth_token = extract_cookie(response_headers, f"AUTH-{auth_pm_uid}")
    new_refresh_token = extract_cookie(response_headers, f"REFRESH-{auth_pm_uid}")
    new_session_id = extract_cookie(response_headers, "Session-Id")

    if not (new_auth_token and new_refresh_token and new_session_id):
        raise WebException(
            "Failed to extract new tokens from refresh response",
            status,
            "Missing tokens in response",
        )

    print("Successfully refreshed authentication tokens")
    return new_auth_token, new_refresh_token, new_session_id


def fetch_logicals(auth_pm_uid, auth_token, session_id, app_version):
    print("Requesting ProtonVPN logicals API...")

    headers = {
        "x-pm-appversion": app_version,
        "x-pm-uid": auth_pm_uid,
        "Accept": "application/vnd.protonmail.v1+json",
        "Cookie": build_cookie_header(
            {f"AUTH-{auth_pm_uid}": auth_token, "Session-Id": session_id}
        ),
    }

    status, reason, _, body = request_json(
        "account.protonvpn.com", "GET", "/api/vpn/logicals", headers
    )
    if status != 200:
        raise WebException("Failed to fetch data from ProtonVPN.", status, reason)

    return json.loads(body)


def load_base_logicals(path=BASE_LOGICALS_PATH):
    if not os.path.exists(path):
        print(f"Base logicals file {path} not found. Using only API data.")
        return {"LogicalServers": []}

    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        print(f"Error parsing {path}: {error}")
        return {"LogicalServers": []}


def combine_logicals(api_data, base_data):
    servers_by_id = {}
    for data in (base_data, api_data):
        for logical in data.get("LogicalServers", []):
            server_id = logical.get("ID")
            if server_id:
                servers_by_id.setdefault(server_id, logical)

    return {**api_data, "LogicalServers": list(servers_by_id.values())}


def get_unique_exit_ips(logicals):
    exit_ips = {
        server["ExitIP"]
        for logical in logicals.get("LogicalServers", [])
        for server in logical.get("Servers", [])
        if server.get("ExitIP")
    }

    return sorted(exit_ips, key=ipaddress.ip_address)


def write_outputs(exit_ips, combined_data):
    with open("protonvpn_logicals.json", "w", encoding="utf-8") as file:
        json.dump(combined_data, file, indent=2)

    with open("protonvpn_ips.json", "w", encoding="utf-8") as file:
        json.dump(exit_ips, file, indent=2)

    with open("protonvpn_ips.txt", "w", encoding="utf-8") as file:
        file.write(TXT_HEADER)
        file.write("\n".join(exit_ips))


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


def persist_tokens(auth_token, refresh_token, session_id):
    os.environ["AUTH_TOKEN"] = auth_token
    os.environ["REFRESH_TOKEN"] = refresh_token
    os.environ["SESSION_ID"] = session_id

    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    with open(".env", "a", encoding="utf-8") as file:
        file.write(f"AUTH_TOKEN={auth_token}\n")
        file.write(f"REFRESH_TOKEN={refresh_token}\n")
        file.write(f"SESSION_ID={session_id}\n")


def main():
    load_dotenv()

    auth_pm_uid = os.environ.get("AUTH_PM_UID")
    auth_token = os.environ.get("AUTH_TOKEN")
    session_id = os.environ.get("SESSION_ID")
    refresh_token = os.environ.get("REFRESH_TOKEN")
    app_version = get_latest_app_version()

    if refresh_token and auth_pm_uid and app_version:
        try:
            auth_token, refresh_token, session_id = refresh_auth_token(
                auth_pm_uid, refresh_token, app_version
            )
            persist_tokens(auth_token, refresh_token, session_id)
        except WebException as error:
            print(f"Token refresh failed: {error}")

    api_data = fetch_logicals(auth_pm_uid, auth_token, session_id, app_version)
    combined_data = combine_logicals(api_data, load_base_logicals())
    exit_ips = get_unique_exit_ips(combined_data)

    write_outputs(exit_ips, combined_data)

    print("\nSummary:")
    print(f"Total logical servers: {len(combined_data.get('LogicalServers', []))}")
    print(f"Total unique Exit IPs found: {len(exit_ips)}")

    print_distribution(exit_ips)


if __name__ == "__main__":
    main()
