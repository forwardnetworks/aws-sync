# AWS Account Sync — End-to-End Flow

This document shows how `awssync` runs end to end in both operational modes,
the connection types and direction between each component, and the permissions
required at each layer. It is intended for architecture review and approval
workflows.

GitHub renders the Mermaid diagrams below automatically.

---

## Mode 1 — Batch / manual

Operator or scheduler invokes `awssync` directly.

```mermaid
flowchart TB
    subgraph triggers["Triggers"]
        cli["Operator CLI\nmanual run"]
        cron["Scheduler / cron\nperiodic sync"]
    end

    preflight["awssync preflight\nread-only checks\nGET /cloudAccounts, POST /nqe"]

    subgraph plan_apply["awssync — plan and apply"]
        plan["plan / dry-run\nPOST /nqe + GET /cloudAccounts"]
        disk["payload.json\nwritten to disk before any change"]
        apply["--apply\nPATCH /cloudAccounts/{setupId}"]
        apply_plan["apply-plan\napply pre-reviewed file from disk"]
    end

    subgraph fwd["Forward platform  (HTTPS · Basic Auth)"]
        nqe["POST /api/nqe\ndiscover AWS accounts"]
        get_accts["GET /cloudAccounts\nread setup metadata"]
        patch_accts["PATCH /cloudAccounts/{setupId}\nwrite account list"]
        get_snap["GET /snapshots/latestProcessed\nsnapshot age check"]
    end

    cli --> preflight
    cron --> preflight
    cli --> plan
    cron --> plan

    preflight -- "read-only" --> fwd
    plan --> disk
    disk --> apply
    disk --> apply_plan
    apply --> patch_accts
    apply_plan --> patch_accts
    plan --> nqe
    plan --> get_accts
    plan --> get_snap

    classDef neutral fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A;
    classDef fwdnode fill:#E6F1FB,stroke:#185FA5,color:#042C53;
    classDef artifact fill:#FAEEDA,stroke:#854F0B,color:#412402;

    class cli,cron,preflight neutral;
    class plan,apply,apply_plan neutral;
    class nqe,get_accts,patch_accts,get_snap fwdnode;
    class disk artifact;
```

---

## Mode 2 — Webhook daemon

`awssync serve-webhook` runs as a long-lived HTTP server. Forward calls it on
each `SNAPSHOT_READY` event. Traffic direction is **inbound to awssync**.

```mermaid
flowchart TB
    subgraph setup["One-time setup (configure-webhook)"]
        cfg["awssync configure-webhook\nregisters webhook URL in Forward\nPOST /webhooks  (HTTPS · Basic Auth)"]
    end

    subgraph daemon["awssync serve-webhook  (long-lived process)"]
        recv["HTTP receiver\nlistens on configured port\nBasic Auth protected"]
        sync["plan + PATCH\nsame as batch mode\nbut pinned to event snapshot ID"]
    end

    subgraph fwd["Forward platform"]
        webhook_out["SNAPSHOT_READY event\nHTTP POST to receiver URL\nBasic Auth"]
        nqe2["POST /api/nqe\n(pinned to snapshot ID)"]
        patch2["PATCH /cloudAccounts/{setupId}"]
    end

    cfg -- "HTTPS · Basic Auth\nFWD_USER / FWD_PASS" --> fwd
    webhook_out -- "inbound HTTP\nBasic Auth (shared secret)" --> recv
    recv --> sync
    sync --> nqe2
    sync --> patch2

    note["Network requirement:\nForward must be able to reach the\nreceiver URL over the network.\nSaaS Forward requires a public endpoint."]

    classDef neutral fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A;
    classDef fwdnode fill:#E6F1FB,stroke:#185FA5,color:#042C53;
    classDef warn fill:#FAEEDA,stroke:#854F0B,color:#412402;

    class cfg,recv,sync neutral;
    class webhook_out,nqe2,patch2 fwdnode;
    class note warn;
```

---

## AWS credential modes (Forward → AWS)

`awssync` holds no AWS credentials. The following two modes describe how
**Forward** connects to AWS. Both end in `sts:AssumeRole` per member account.

```mermaid
flowchart LR
    subgraph mode_role["IAM role mode"]
        fwd_role["Forward\nIAM role"]
        org_role["AWS Organizations\nmanagement / delegated acct\norganizations:ListAccounts"]
        member_role["Member accounts\nForwardRole\nsts:AssumeRole"]
        fwd_role --> org_role
        fwd_role --> member_role
    end

    subgraph mode_key["IAM user / access-key mode"]
        fwd_key["Forward\naccess key credential"]
        org_key["AWS Organizations\nmanagement / delegated acct\norganizations:ListAccounts"]
        member_key["Member accounts\nForwardRole\nsts:AssumeRole"]
        fwd_key --> org_key
        fwd_key --> member_key
    end

    classDef fwdnode fill:#E6F1FB,stroke:#185FA5,color:#042C53;
    classDef awsnode fill:#E1F5EE,stroke:#0F6E56,color:#04342C;

    class fwd_role,fwd_key fwdnode;
    class org_role,member_role,org_key,member_key awsnode;
```

---

## Permissions summary

### awssync → Forward

| API call | Purpose | Required Forward permission |
| --- | --- | --- |
| `POST /api/nqe` | Discover AWS accounts | read NQE |
| `GET /networks` | Resolve network ID | read networks |
| `GET /cloudAccounts` | Read setup metadata | read cloud accounts |
| `PATCH /cloudAccounts/{id}` | Write account list | write cloud accounts |
| `GET /snapshots/latestProcessed` | Check snapshot age | read snapshots |
| `POST /webhooks` | Register webhook | manage webhooks |

### Forward → AWS (both credential modes)

| Where | Permission | Purpose |
| --- | --- | --- |
| Org management / delegated account | `organizations:ListAccounts` | discover account inventory |
| Each member account | `ForwardRole` IAM role exists | collection target |
| Each member account | Trust policy allows Forward to assume role | `sts:AssumeRole` |
| Each member account | Read permissions on network resources | collection |

### Webhook receiver (inbound)

| What | Detail |
| --- | --- |
| Listening port | Configurable (default example: `:8080`) |
| Protocol | HTTP (TLS terminated at reverse proxy recommended for production) |
| Authentication | HTTP Basic Auth — shared secret between Forward and receiver |
| Caller | Forward platform (SaaS: internet; on-prem: Forward app server) |

---

## Key security properties

- `awssync` **never connects to AWS** and holds no AWS credentials.
- `awssync` only reads from and writes to the Forward platform API.
- The payload JSON is **always written to disk before any PATCH** — changes can be reviewed before or instead of applying.
- Removals require explicit `--allow-removals` flag; `awssync` will not silently
  remove accounts from a Forward setup.
- Webhook receiver is protected by HTTP Basic Auth with a shared secret
  independent of Forward user credentials.

For the full operational procedure see
[AWS Account Sync Procedure](aws-account-sync-procedure.md).
