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
    parser.add_argument('--dry-run', action='store_true', help='Build payloads only; skip PATCH requests')
    parser.add_argument('--yes', action='store_true', help='Skip confirmation prompt and PATCH immediately')
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
    meta = {}
    for acct in accounts:
        setup_id = acct.get("name")
        if not setup_id:
            continue
        meta[setup_id] = {
            "setupId": setup_id,
            "proxyServerId": acct.get("proxyServerId"),
            "regions": acct.get("regions", {}),
            "assumeRoleInfos": acct.get("assumeRoleInfos", [])
        }
    return meta

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

def group_accounts_by_setup(items):
    grouped = {}
    for item in items:
        setup_id = (
            item.get("Setup ID")
            or item.get("Cloud Account Setup ID")
            or item.get("Cloud Account Setup")
        )
        account_id = item.get("Cloud Account ID")
        account_name = item.get("Cloud Account Name", account_id)
        if not setup_id or not account_id:
            continue
        grouped.setdefault(setup_id, []).append({
            "Cloud Account ID": account_id,
            "Cloud Account Name": account_name
        })
    return grouped

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
    cloud_meta_map = get_cloud_account_meta(args)
    if not cloud_meta_map:
        print("Error: No cloud account metadata available in Forward. Aborting.")
        return
    if len(cloud_meta_map) > 1 and args.query_id == DEFAULT_QUERY_ID:
        print(
            "Multiple Forward setup IDs detected. Provide a custom NQE that includes setup ID "+
            "data (e.g. Q_87ae9239148d19c940714200830f657927541253) and rerun."
        )
        return
    grouped_accounts = group_accounts_by_setup(items)

    if not grouped_accounts:
        fallback_setup = next(iter(cloud_meta_map.keys()), None)
        fallback_accounts = []
        for item in items:
            account_id = item.get("Cloud Account ID")
            account_name = item.get("Cloud Account Name", account_id)
            if not account_id:
                continue
            fallback_accounts.append({
                "Cloud Account ID": account_id,
                "Cloud Account Name": account_name
            })
        if fallback_setup and fallback_accounts:
            grouped_accounts[fallback_setup] = fallback_accounts
            print(
                f"No setup IDs found in query output; defaulting all accounts to setup '{fallback_setup}'."
            )

    if not grouped_accounts:
        print("No AWS accounts found in query response. Nothing to do.")
        return

    current_epoch_ms = int(time.time() * 1000)
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    audit_payloads = {}
    pending_patches = []

    for setup_id, aws_accounts in grouped_accounts.items():
        cloud_meta = cloud_meta_map.get(setup_id)
        if not cloud_meta:
            print(f"⚠️  No cloud account metadata found for setup ID '{setup_id}'. Skipping.")
            continue

        role_arn_name = extract_role_name(cloud_meta.get("assumeRoleInfos", []))
        if not role_arn_name:
            print(f"⚠️  Unable to determine role ARN for setup ID '{setup_id}'. Skipping.")
            continue

        org_id = extract_org_id(cloud_meta.get("assumeRoleInfos", []))
        formatted_accounts = build_assume_role_infos(aws_accounts, role_arn_name, org_id)

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

        audit_payloads[setup_id] = patch_payload
        pending_patches.append({
            "setup_id": setup_id,
            "payload": patch_payload,
            "role": role_arn_name,
            "org_id": org_id,
            "proxy_id": cloud_meta.get("proxyServerId"),
            "regions": region_map,
            "account_count": len(formatted_accounts)
        })

    if not pending_patches:
        print("No eligible setups found to PATCH. Exiting.")
        return

    with open("aws_patch_payload.json", "w") as f:
        json.dump(audit_payloads, f, indent=2)
    print(f"Saved audit payloads for {len(pending_patches)} setup(s) to aws_patch_payload.json")

    print(f"\nPrepared payloads for {len(pending_patches)} setup(s). Review details below:")
    for patch in pending_patches:
        regions = patch["regions"].keys()
        print(f"\nSetup ID: {patch['setup_id']}")
        print(f"Role Name: {patch['role']}")
        if patch["org_id"]:
            print(f"Org ID: {patch['org_id']}")
        if patch["proxy_id"]:
            print(f"Proxy Server ID: {patch['proxy_id']}")
        print(f"Regions: {', '.join(regions) or 'None'}")
        print(f"Accounts to PATCH: {patch['account_count']}")

    print("\nPayloads written to aws_patch_payload.json. Inspect before continuing if needed.")

    if args.dry_run:
        print("Dry run enabled; skipping PATCH requests.")
        return

    if not args.yes:
        proceed = input("Proceed with PATCH requests? [y/N]: ").strip().lower()
        if proceed not in ("y", "yes"):
            print("Aborting before PATCH.")
            return

    for patch in pending_patches:
        setup_id = patch["setup_id"]
        patch_url = f"{args.host}/api/networks/{args.network_id}/cloudAccounts/{setup_id}"
        print(f"\nPATCHing setup '{setup_id}' with {patch['account_count']} accounts...")
        patch_response = requests.patch(
            patch_url,
            headers=headers,
            auth=HTTPBasicAuth(args.username, args.password),
            json=patch["payload"],
            verify=not args.insecure
        )

        if patch_response.status_code == 200:
            print("✅ PATCH successful.")
        else:
            print(f"❌ PATCH failed with status {patch_response.status_code}")
            print(patch_response.text)

if __name__ == "__main__":
    main()
