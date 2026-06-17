# AWS Account Sync — End-to-End Flow

This diagram shows how `awssync` runs end to end, the connection types between
each component, and the permissions required at each layer. It is intended for
architecture review and approval workflows.

GitHub renders the Mermaid diagram below automatically.

## Flow

```mermaid
flowchart TB
    subgraph triggers["Triggers"]
        cli["Operator (CLI)<br/><small>manual dry-run / apply</small>"]
        cron["Scheduler / cron<br/><small>periodic sync</small>"]
        hook["Forward webhook<br/><small>SNAPSHOT_READY event</small>"]
    end

    sync["<b>awssync</b><br/><small>plan &rarr; write payload &rarr; optional PATCH</small>"]

    subgraph fwd["Forward platform (SaaS or on-prem)"]
        nqe["POST /api/nqe<br/><small>discover AWS accounts</small>"]
        get["GET /cloudAccounts<br/><small>read setup metadata</small>"]
        patch["PATCH /cloudAccounts/{setupId}<br/><small>write account list</small>"]
    end

    subgraph aws["AWS"]
        org["AWS Organizations<br/>management / delegated acct<br/><small>organizations:ListAccounts</small>"]
        member["AWS member accounts<br/>per collected account<br/><small>ForwardRole &middot; sts:AssumeRole</small>"]
    end

    cli --> sync
    cron --> sync
    hook --> sync

    sync -- "HTTPS &middot; Basic Auth (FWD_USER / FWD_PASS)" --> fwd

    fwd -- "account inventory" --> org
    fwd -- "collection / assume role" --> member

    classDef neutral fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A;
    classDef forward fill:#E6F1FB,stroke:#185FA5,color:#042C53;
    classDef awsnode fill:#E1F5EE,stroke:#0F6E56,color:#04342C;

    class cli,cron,hook,sync neutral;
    class nqe,get,patch forward;
    class org,member awsnode;
```

## Connection types

Only two connection types exist:

- **`awssync` &rarr; Forward** — HTTPS REST, HTTP Basic Auth (`FWD_USER` / `FWD_PASS`).
  The same Basic Auth model secures the webhook receiver (`serve-webhook`).
- **Forward &rarr; AWS** — AWS APIs using IAM (role or access key) plus
  `sts:AssumeRole` per account.

`awssync` never connects to AWS and holds no AWS credentials. It only reads from
and writes to the Forward platform.

## Permissions required

| Layer | Where | Permission |
| --- | --- | --- |
| Forward user | Forward platform | read NQE, read/PATCH `cloudAccounts`, manage webhooks |
| AWS discovery | Org management / delegated account | `organizations:ListAccounts` |
| AWS collection | each member account | `ForwardRole` exists, trust policy allows Forward, `sts:AssumeRole`, read permissions |

## Two-layer model

1. **AWS Organizations** tells Forward which accounts exist.
2. **IAM roles** in each AWS account let Forward collect those accounts.

`awssync` automates layer 1 into Forward's configured account list. Layer 2 must
already exist in AWS: a newly added account appears in Forward but fails
collection until the expected IAM role and trust policy are in place.

For the full operational procedure, see
[AWS Account Sync Procedure](aws-account-sync-procedure.md).
