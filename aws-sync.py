import requests
import json
import argparse
import os
import time
from requests.auth import HTTPBasicAuth

DEFAULT_QUERY_ID = "FQ_6d355dca16ed9aae1eb7ad152c7fd13ccdf082fa"
PAGE_LIMIT = 1000

def get_args():
    parser = argparse.ArgumentParser(description="Prepare and PATCH AWS payload to Forward Networks")
    parser.add_argument('--host', default=os.getenv('FWD_HOST'), help='Forward host URL')
    parser.add_argument('--network-id', type=int, default=os.getenv('FWD_NETWORK_ID'), help='Forward network ID')
    parser.add_argument('--query-id', default=os.getenv('FWD_QUERY_ID', DEFAULT_QUERY_ID), help='NQE query ID')
    parser.add_argument('--username', default=os.getenv('FWD_USERNAME'), help='Username for basic auth')
    parser.add_argument('--password', default=os.getenv('FWD_PASSWORD'), help='Password for basic auth')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL verification')
    args = parser.parse_args()

    required_fields = {
        "host": args.host,
        "network_id": args.network_id,
        "username": args.username,
        "password": args.password,
    }
    missing = [key for key, val in required_fields.items() if val is None]
    if missing:
        parser.error(f"Missing required argument(s): {', '.join('--' + m.replace('_', '-') for m in missing)}")

    return args

def fetch_all_items(args):
    all_items = []
    offset = 0
    while True:
        url = f"{args.host}/api/nqe?networkId={args.network_id}"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        payload = {
            "queryId": args.query_id,
            "queryOptions": {
                "offset": offset,
                "limit": PAGE_LIMIT,
                "columnFilters": [
                    {
                        "columnName": "Cloud Type",
                        "value": "AWS"
                    }
                ]
            }
        }
        response = requests.post(
            url, headers=headers, json=payload,
            auth=HTTPBasicAuth(args.username, args.password),
            verify=not args.insecure
        )
        response.raise_for_status()
        data = response.json()
        items = data.get("items", [])
        print(f"Fetched {len(items)} items at offset {offset}")
        all_items.extend(items)
        if len(items) < PAGE_LIMIT:
            break
        offset += PAGE_LIMIT
    return all_items

def get_cloud_account_meta(args):
    url = f"{args.host}/api/networks/{args.network_id}/cloudAccounts"
    headers = {"accept": "application/json"}
    response = requests.get(
        url, headers=headers,
        auth=HTTPBasicAuth(args.username, args.password),
        verify=not args.insecure
    )
    response.raise_for_status()
    accounts = response.json()
    for acct in accounts:
        if acct.get("name") and acct.get("regions"):
            return {
                "setupId": acct["name"],
                "proxyServerId": acct.get("proxyServerId"),
                "regions": acct.get("regions", {}),
                "assumeRoleInfos": acct.get("assumeRoleInfos", [])
            }
    return {"setupId": None, "proxyServerId": None, "regions": {}, "assumeRoleInfos": []}

def extract_role_name(assume_role_infos):
    for info in assume_role_infos:
        arn = info.get("roleArn", "")
        if ":role/" in arn:
            return arn.split(":role/")[-1]
    return None

def extract_org_id(assume_role_infos):
    for info in assume_role_infos:
        ext_id = info.get("externalId")
        if ext_id and ext_id.startswith("Org:"):
            return int(ext_id.split("Org:")[-1])
    return None

def build_assume_role_infos(aws_accounts, role_arn_name, org_id=None):
    result = []
    for acct in aws_accounts:
        account_id = acct["Cloud Account ID"]
        account_name = acct["Cloud Account Name"]
        entry = {
            "accountId": account_id,
            "accountName": account_name,
            "roleArn": f"arn:aws:iam::{account_id}:role/{role_arn_name}",
            "externalId": f"Org:{org_id}" if org_id else None,
            "enabled": True
        }
        result.append(entry)
    return result

def main():
    args = get_args()
    items = fetch_all_items(args)
    cloud_meta = get_cloud_account_meta(args)

    setup_id = cloud_meta.get("setupId")
    role_arn_name = extract_role_name(cloud_meta.get("assumeRoleInfos", []))
    org_id = extract_org_id(cloud_meta.get("assumeRoleInfos", []))

    if not role_arn_name or not setup_id:
        print("Error: Missing setup ID or role ARN.")
        exit(1)

    aws_accounts = [
        {
            "Cloud Account ID": item["Cloud Account ID"],
            "Cloud Account Name": item["Cloud Account Name"]
        }
        for item in items
    ]

    formatted_accounts = build_assume_role_infos(aws_accounts, role_arn_name, org_id)

    current_epoch_ms = int(time.time() * 1000)
    region_map = {
        region: meta.get("testInstant", current_epoch_ms)
        for region, meta in cloud_meta.get("regions", {}).items()
    }

    patch_payload = {
        "type": "AWS",
        "name": setup_id,
        "regions": region_map,
        "regionToProxyServerId": {},
        "assumeRoleInfos": formatted_accounts
    }

    if cloud_meta.get("proxyServerId"):
        patch_payload["proxyServerId"] = cloud_meta["proxyServerId"]

    # Save locally for audit
    with open("aws_patch_payload.json", "w") as f:
        json.dump(patch_payload, f, indent=2)

    print(f"\nSetup ID: {setup_id}")
    print(f"Role Name: {role_arn_name}")
    if org_id:
        print(f"Org ID: {org_id}")
    if cloud_meta.get("proxyServerId"):
        print(f"Proxy Server ID: {cloud_meta['proxyServerId']}")
    print(f"Regions: {', '.join(region_map.keys())}")
    print(f"PATCHing {len(formatted_accounts)} accounts to Forward API...")

    # Do PATCH
    patch_url = f"{args.host}/api/networks/{args.network_id}/cloudAccounts/{setup_id}"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }

    patch_response = requests.patch(
        patch_url,
        headers=headers,
        auth=HTTPBasicAuth(args.username, args.password),
        json=patch_payload,
        verify=not args.insecure
    )

    if patch_response.status_code == 200:
        print("✅ PATCH successful.")
    else:
        print(f"❌ PATCH failed with status {patch_response.status_code}")
        print(patch_response.text)

if __name__ == "__main__":
    main()
