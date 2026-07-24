# Routine AWS Safe Sync

This is the operator workflow for updating existing Forward AWS setups. It requires a Forward login, not an AWS console login or AWS CLI profile.

`safe-sync` can add newly discovered accounts and re-enable unchecked accounts. It cannot remove accounts.

## One-Time Setup

Download the appropriate archive and `sha256sums.txt` from [GitHub Releases](https://github.com/forwardnetworks/aws-sync/releases).

```bash
tar -xzf awssync-linux-amd64.tar.gz
sha256sum -c sha256sums.txt --ignore-missing
./awssync-linux-amd64 --version
```

Set the Forward connection information:

```bash
export FWD_HOST=https://fwd.app
export FWD_USER=you@example.com
export FWD_NETWORK_ID=NETWORK_ID
```

Do not save the Forward password in this file. The command prompts for it securely.

## Run the Sync

```bash
./awssync-linux-amd64 safe-sync \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX
```

For one setup, use one `--setup-id`. If the network or setup is not supplied, an interactive terminal can display a numbered picker.

## Review the Preview

Confirm:

- the network and setup IDs are correct;
- the snapshot is current;
- `add` matches expected newly created accounts;
- `reenable` matches expected unchecked accounts;
- `remove=0`.

The prompt requires the complete word:

```text
apply
```

Any other response cancels the operation.

## Confirm Completion

A successful run prints:

- the number of patched setups;
- the rollback file path;
- the rollback SHA-256.

Keep the rollback file until the next successful collection confirms the expected account state.

## If Safe Sync Stops

Do not add advanced flags. Record the complete error and check:

1. Does the network have a processed snapshot from the last 24 hours?
2. Is the correct multi-account AWS setup selected?
3. Does Forward NQE show AWS accounts for that setup?
4. Is the AWS Organizations management or delegated discovery account being collected?
5. For a failed member account, does its IAM role trust the configured Forward identity and use the matching External ID?

A collection failure does not mean an account should be removed. Repair IAM, role trust, External ID, or collection permissions first.

## Account Removal

Routine operators should not remove accounts with this tool. Escalate a removal to an operator who can independently verify the AWS account lifecycle and follow the reviewed removal procedure in [AWS account sync procedure](aws-account-sync-procedure.md#apply-the-sync).
