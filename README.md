# AWS Sync Tool for Forward Networks

This script automates the collection and synchronization of AWS account information into a Forward Networks environment.

## Purpose

This utility:
- Retrieves AWS account IDs and names using a Network Query Engine (NQE) query.
- Matches those accounts with existing setup IDs in Forward.
- Extracts metadata such as `proxyServerId`, region timestamps, and role ARN.
- Constructs and PATCHes the required JSON payload back into the platform to update AWS cloud account configurations.

## Requirements

- A consistent IAM role name across all AWS accounts.
- Valid Forward Networks credentials with access to the target network.
- AWS Organizations API access from Forward Networks collection
- Python 3.8+ and `requests` module (see `requirements.txt`).

## Usage

```bash
python3 aws-sync.py \
  --host https://<forward-host> \
  --network-id <network_id> \
  --username <your_forward_username> \
  --password <your_forward_password> \
```

### Optional arguments:
- `--query-id`: Custom query ID (default is pre-configured in script).
- `--insecure`: Disable SSL verification (not recommended for production).

All arguments can also be passed via environment variables:
- `FWD_HOST`
- `FWD_NETWORK_ID`
- `FWD_QUERY_ID`
- `FWD_USERNAME`
- `FWD_PASSWORD`

## Example

```bash
python3 aws-sync.py \
  --host https://fwd.app \
  --network-id <network_id> \
  --username <your_username> \
  --password <your_password>
```

This script will:
- Retrieve all AWS accounts via NQE.
- Identify the matching setup ID(s) from your Forward deployment.
- Generate and PATCH the configuration JSON to keep cloud sync up-to-date.

## License

© Forward Networks, Inc. MIT License or internal use only, based on your distribution preferences.
