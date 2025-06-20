#!/usr/bin/env python3
"""
aruba_export.py

Interactive export of Aruba Central WLAN configuration:
  - Prompts for region to pick the right API gateway
  - Prompts for your API token
  - Exports SSID, AP, auth, DHCP profiles into one JSON summary
"""

import requests
import json
import sys
import getpass

# map “region code” → API gateway base URL
REGION_URLS = {
    'US-1':      'https://app1-apigw.central.arubanetworks.com',
    'US-2':      'https://apigw-prod2.central.arubanetworks.com',
    'US-East1':  'https://apigw-us-east-1.central.arubanetworks.com',
    'US-West4':  'https://apigw-uswest4.central.arubanetworks.com',
    'US-West5':  'https://apigw-uswest5.central.arubanetworks.com',
    'EU-1':      'https://eu-apigw.central.arubanetworks.com',
    'EU-Central2':'https://apigw-eucentral2.central.arubanetworks.com',
    'EU-Central3':'https://apigw-eucentral3.central.arubanetworks.com',
    'Canada-1':  'https://apigw-ca.central.arubanetworks.com',
    'China-1':   'https://apigw.central.arubanetworks.com.cn',
    'APAC-1':    'https://api-ap.central.arubanetworks.com',
    'APAC-EAST1':'https://apigw-apaceast.central.arubanetworks.com',
    'APAC-SOUTH1':'https://apigw-apacsouth.central.arubanetworks.com',
    'UAE-NORTH1':'https://apigw-uaenorth1.central.arubanetworks.com',
}

def choose_region():
    print("Available regions:")
    for code in sorted(REGION_URLS):
        print(f"  • {code}")
    region = input("\nEnter your region code (e.g. US-1): ").strip()
    base = REGION_URLS.get(region)
    if not base:
        print(f"❌ Unknown region '{region}'. Exiting.", file=sys.stderr)
        sys.exit(1)
    return base

def build_headers(token: str) -> dict:
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

def fetch(endpoint: str, base_url: str, headers: dict, params: dict = None) -> dict:
    url = base_url.rstrip('/') + endpoint
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

def main():
    print("\n🔧 Aruba Central Migration Export\n")
    base_url = choose_region()
    token = getpass.getpass("Enter your Aruba Central API token: ").strip()
    headers = build_headers(token)

    summary = {}
    try:
        print("\nFetching SSID configurations…")
        summary['ssids'] = fetch('/configuration/v1/ssids', base_url, headers)

        print("Fetching Access Point configurations…")
        summary['access_points'] = fetch('/configuration/v1/accesspoints', base_url, headers)

        print("Fetching RADIUS/auth profiles…")
        summary['auth_profiles'] = fetch('/configuration/v1/authprofiles', base_url, headers)

        print("Fetching DHCP server profiles…")
        summary['dhcp_profiles'] = fetch('/configuration/v1/dhcpservers', base_url, headers)

        # add any other endpoints you need here…
        # e.g. syslog, SNMP, NTP: fetch('/configuration/v1/syslogservers', base_url, headers)
    except requests.HTTPError as e:
        print(f"❌ API error: {e} → {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(2)

    out_file = 'aruba_migration_summary.json'
    with open(out_file, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n✅ Export complete! Summary written to: {out_file}\n")

if __name__ == '__main__':
    main()
