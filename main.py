#!/usr/bin/env python3
import urllib.request
import urllib.error
import http.client
import http.cookies
import json
import os
from typing import List, Any, Dict, Optional


class WebException(Exception):
    """Exception raised for HTTP errors with status code information."""

    def __init__(self, message, status_code, reason):
        self.message = message
        self.status_code = status_code
        self.reason = reason
        super().__init__(f"{message} Status: {status_code}, reason: {reason}")


def load_dotenv(env_file=".env"):
    """
    Load environment variables from a .env file into os.environ

    Args:
        env_file: Path to the .env file (default: ".env")
    """
    if not os.path.exists(env_file):
        return

    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]

                os.environ[key] = value

    print(f"Loaded environment variables from {env_file}")


def fetch_protonvpn_data(
    auth_pm_uid, auth_token, session_id, web_app_version
) -> Dict[str, Any]:
    """
    Fetch ProtonVPN logicals and save the unique exit IPs to a JSON file.

    Args:
        auth_pm_uid: The PM user ID for authentication
        auth_token: The authentication token
        session_id: The session ID
        web_app_version: The web app version string
    """
    auth_cookies = http.cookies.SimpleCookie()
    auth_cookies["AUTH-" + auth_pm_uid] = auth_token
    auth_cookies["Session-Id"] = session_id

    headers = {
        "x-pm-appversion": web_app_version,
        "x-pm-uid": auth_pm_uid,
        "Accept": "application/vnd.protonmail.v1+json",
        "Cookie": auth_cookies.output(attrs=[], header="", sep="; "),
    }

    print("Requesting ProtonVPN logicals API...")
    connection = http.client.HTTPSConnection("account.protonvpn.com")
    connection.request("GET", "/api/vpn/logicals", headers=headers)
    response = connection.getresponse()
    if response.status != 200:
        raise WebException(
            "Failed to fetch data from ProtonVPN.", response.status, response.reason
        )

    data = response.read().decode()
    response_json = json.loads(data)

    with open("protonvpn_logicals.json", "w", encoding="utf-8") as f:
        json.dump(response_json, f, indent=2)

    connection.close()

    return response_json


def load_base_logicals(base_file="dev_base.json") -> Dict[str, Any]:
    """
    Load base logicals from the specified JSON file.

    Args:
        base_file: Path to the base logicals JSON file

    Returns:
        Dictionary containing the base logicals data
    """
    if not os.path.exists(base_file):
        print(f"Base logicals file {base_file} not found. Using only API data.")
        return {"LogicalServers": []}

    try:
        with open(base_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing {base_file}: {e}")
        return {"LogicalServers": []}


def combine_logicals(
    api_data: Dict[str, Any], base_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Combine logical servers from API and base data, removing duplicates.

    Args:
        api_data: Logicals data from the API
        base_data: Base logicals data

    Returns:
        Combined logicals data
    """
    server_ids = set()
    combined_logicals = []

    for logical in api_data.get("LogicalServers", []):
        server_id = logical.get("ID")
        if server_id and server_id not in server_ids:
            server_ids.add(server_id)
            combined_logicals.append(logical)

    for logical in base_data.get("LogicalServers", []):
        server_id = logical.get("ID")
        if server_id and server_id not in server_ids:
            server_ids.add(server_id)
            combined_logicals.append(logical)

    result = api_data.copy()
    result["LogicalServers"] = combined_logicals

    return result


def get_unique_exit_ips(data: Dict[str, Any]) -> List[str]:
    """
    Get unique exit IPs from ProtonVPN logicals.
    """
    exit_ips: List[str] = []
    for logical_server in data.get("LogicalServers", []):
        for server in logical_server.get("Servers", []):
            exit_ip = server.get("ExitIP")
            if exit_ip:
                exit_ips.append(exit_ip)

    unique_exit_ips: List[str] = list(set(exit_ips))

    return unique_exit_ips


def get_latest_protonvpn_version() -> Optional[str]:
    """
    Gets the latest version of protonvpn web
    """
    url = "https://account.protonvpn.com/assets/yandex-browser-manifest.json"

    try:
        with urllib.request.urlopen(url) as response:
            data = json.load(response)

            return f"web-vpn-settings@{data['version']}"
    except (urllib.error.URLError, KeyError):
        pass

    return None


def main() -> None:
    """
    Fetch ProtonVPN logicals and save the unique exit IPs to a JSON file.
    """
    load_dotenv()

    auth_pm_uid = os.environ.get("AUTH_PM_UID")
    auth_token = os.environ.get("AUTH_TOKEN")
    session_id = os.environ.get("SESSION_ID")
    web_app_version = get_latest_protonvpn_version()
    if not web_app_version:
        web_app_version = os.environ.get("WEB_APP_VERSION")

    if not auth_pm_uid or not auth_token or not session_id:
        print("Missing required authentication parameters.")
        if not auth_pm_uid:
            auth_pm_uid = input("Please enter your AUTH_PM_UID: ")
        if not auth_token:
            auth_token = input("Please enter your AUTH_TOKEN: ")
        if not session_id:
            session_id = input("Please enter your SESSION_ID: ")

    api_data: Dict[str, Any] = fetch_protonvpn_data(
        auth_pm_uid, auth_token, session_id, web_app_version
    )

    base_data: Dict[str, Any] = load_base_logicals()

    combined_data: Dict[str, Any] = combine_logicals(api_data, base_data)

    with open("protonvpn_logicals.json", "w", encoding="utf-8") as f:
        json.dump(combined_data, f, indent=2)

    unique_exit_ips: List[str] = get_unique_exit_ips(combined_data)

    with open("protonvpn_ips.json", "w", encoding="utf-8") as f:
        json.dump(unique_exit_ips, f, indent=2)

    with open("protonvpn_ips.txt", "w", encoding="utf-8") as f:
        for ip in unique_exit_ips:
            f.write(f"{ip}\n")

    print(
        f"Found {len(combined_data.get('LogicalServers', []))} unique logical"
        f"servers with {len(unique_exit_ips)} unique exit IPs."
    )


if __name__ == "__main__":
    main()
