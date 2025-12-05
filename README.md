# AWS Sync Tool for Forward Networks

This script automates the collection and synchronization of AWS account information into a Forward Networks environment. It supports multiple Forward setup IDs at once and writes each PATCH payload to disk for review before any API updates occur.

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
- `--dry-run`: Build payloads and save `aws_patch_payload.json`, but skip the PATCH requests.
- `--yes`: Skip the confirmation prompt (safe for automation once payloads are verified).

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
- Group accounts by setup ID when the query includes that column (required when multiple setups exist), otherwise fall back to the single available setup.
- Save the planned PATCH payload(s) into `aws_patch_payload.json` for verification.
- Prompt for confirmation (unless `--dry-run` or `--yes` is provided) and PATCH each setup accordingly.

### Multiple setup IDs

If your Forward network contains multiple AWS setup IDs, the default query will detect this and exit. Provide a custom NQE that includes a `Setup ID` column—such as `Q_87ae9239148d19c940714200830f657927541253`—via the `--query-id` argument or `FWD_QUERY_ID` environment variable before running the script.

## License

© Forward Networks, Inc. MIT License or internal use only, based on your distribution preferences.
