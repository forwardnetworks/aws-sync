# Security review notes

For teams that have to approve `awssync` before running it. This describes what the tool does, so you can check it against the source.

## What it talks to

`safe-sync`, `external-id`, `external-id-status`, `preflight`, `status`, `wait` and `apply-plan` talk only to your Forward instance (`FWD_HOST`), through the published [forward-go-sdk](https://github.com/forwardnetworks/forward-go-sdk). They never call AWS and need no AWS credentials.

The one exception is `discover-org` (and `onboard-accounts`, which builds on it). It reads AWS Organizations with your AWS credentials to prepare a new setup. You don't need either for `safe-sync` or External IDs. The AWS SDK appears in the SBOM because it is compiled into the binary.

Requests the Forward-only commands make:

| Purpose | Request |
| --- | --- |
| List networks, snapshots | `GET` |
| Read the AWS setups | `GET /api/networks/{id}/cloudAccounts` |
| Read discovered accounts | `POST /api/nqe` (a read-only query) |
| Change a setup | `PATCH /api/networks/{id}/cloudAccounts/{setup}` |

The PATCH is the only write to an existing setup's account list. It goes through one function (`GuardAndApply`), and a test fails if a second caller of the PATCH appears.

Two other commands write to Forward, and only when you ask. `discover-org --post` and `onboard-accounts --post` create a new AWS setup (`POST` to `cloudAccounts`, with a confirmation prompt). `configure-webhook` creates or updates a Forward webhook. Neither is part of `safe-sync` or External IDs.

## What a write can change

- `safe-sync` adds or re-enables accounts in a setup. It never removes or disables any.
- `external-id` sets or clears the External ID on accounts you name.
- Nothing else changes. Regions, proxy settings and unselected accounts are left alone. The tool never sends `regions`, because Forward would record each one as a freshly passed connectivity test.
- `external-id-status` is read-only and never prints, returns or writes a value.

Removing accounts is a separate command (`sync-accounts`) that needs a reviewed manifest, `--allow-removals` and size ceilings.

## Controls before a write

- Dry run by default. `safe-sync` shows a preview and waits for you to type `apply` (`--yes` skips the prompt, so don't use it in a first test).
- The apply is bound to the digest of the reviewed plan. If the plan changes, it stops.
- If the plan has no differences, nothing is sent.
- It re-reads the setup just before the PATCH and stops if the setup changed since the plan. This is a best-effort check, not atomic, because Forward offers no compare-and-swap. An edit made inside the PATCH window itself is not caught.
- It writes a rollback file before the PATCH. The file holds the pre-change PATCH payload, not a full backup of the setup. `apply-plan --plan <file>.rollback.json` restores that state.
- An apply writes a per-setup result journal.

## Credentials

- The Forward password is prompted for and not echoed. It can also come from `FWD_PASSWORD`. Use an account with only the access you want the tool to have.
- Error messages never repeat an External ID value, or the cells of an External ID file or `--account-id` input. Other errors can quote an account or setup ID from your input files.
- Generated payload files are written with restrictive permissions and may contain tenant data. Don't commit them.

## Verifying the release

Each release publishes checksums, an SBOM (`sbom.spdx.json`) and GitHub build-provenance attestations for the binaries, the archives and the SBOM.

```bash
sha256sum -c sha256sums.txt --ignore-missing
gh attestation verify awssync-linux-amd64 --repo forwardnetworks/aws-sync
gh attestation verify sbom.spdx.json --repo forwardnetworks/aws-sync
```

To build it yourself instead, check out the tag and run `make build` (Go version in `go.mod`). CI also runs `go vet`, the race detector and `govulncheck` on every change.

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
