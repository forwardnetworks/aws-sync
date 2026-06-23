# AWS Account Sync — End-to-End Flow

This document shows how `awssync` runs end to end in its operational modes,
the connection types and direction between each component, and the permissions
required at each layer. It is intended for architecture review and approval
workflows.

GitHub renders the Mermaid diagrams below automatically.

---

## Mode 1 — Existing Setup Sync

Operator or scheduler invokes `awssync` directly to update one or more existing Forward AWS setups from Forward NQE data.

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

## Mode 2 — Initial AWS Organizations Onboarding

`awssync discover-org` is for a new Forward AWS setup. It calls AWS Organizations directly, writes the Forward UI upload JSON, writes the Forward create-setup POST body, and can optionally POST that new setup to Forward. It does not PATCH existing setups.

```mermaid
flowchart TB
    subgraph operator["Operator / automation"]
        cli["awssync discover-org\nAWS SDK default chain or --aws-profile"]
        ui_file["fwd_accounts_data_TIMESTAMP.json\nForward UI drag-and-drop file"]
        post_file["aws_create_payload_TIMESTAMP.json\nPOST /cloudAccounts body"]
    end

    subgraph aws["AWS Organizations"]
        describe["DescribeOrganization"]
        list_accounts["ListAccounts"]
        list_parents["ListParents\nOU/root parent evidence"]
    end

    subgraph fwd_create["Forward platform  (optional HTTPS · Basic Auth)"]
        networks["GET /networks\nresolve network"]
        existing["GET /cloudAccounts\nreject duplicate setup name"]
        external["GET /cloudAccounts/aws/assumeRole/externalId"]
        create["POST /cloudAccounts\ncreate new AWS setup"]
    end

    cli --> describe
    cli --> list_accounts
    cli --> list_parents
    cli --> ui_file
    cli --> post_file
    cli -. "when Forward credentials supplied" .-> networks
    cli -. "when Forward credentials supplied" .-> existing
    cli -. "when external ID omitted" .-> external
    post_file -. "--post --yes" .-> create

    classDef neutral fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A;
    classDef fwdnode fill:#E6F1FB,stroke:#185FA5,color:#042C53;
    classDef awsnode fill:#E1F5EE,stroke:#0F6E56,color:#04342C;
    classDef artifact fill:#FAEEDA,stroke:#854F0B,color:#412402;

    class cli neutral;
    class describe,list_accounts,list_parents awsnode;
    class networks,existing,external,create fwdnode;
    class ui_file,post_file artifact;
```

---

## Mode 3 — Native IaC Onboarding With Terraform

For new AWS Organizations onboarding, the preferred automation path is the Forward Terraform provider. Terraform can prepare AWS-side roles, read AWS Organizations, fetch Forward's external ID when needed, and create or update the Forward AWS cloud setup in one plan/apply workflow. The provider supports Forward assume-role, static-key, and collector instance-profile credential models.

```mermaid
flowchart TB
    subgraph tf["Terraform native IaC workflow"]
        aws_provider["AWS provider\nrole / StackSet prerequisites"]
        ext_id["forward_aws_assume_role_external_id\nGET external ID\nforward-assume-role only"]
        org_ds["forward_aws_organization_accounts\nDescribeOrganization, ListAccounts, ListParents"]
        credential_mode["credential_mode\nforward-assume-role\nstatic-keys\ninstance-profile"]
        fwd_resource["forward_aws_cloud_account\nPOST or PATCH /cloudAccounts"]
    end

    subgraph aws["AWS Organizations"]
        org_api["Organization account inventory"]
        member_role["Stable Forward collection role\nin each member account"]
    end

    subgraph fwd_tf["Forward platform"]
        external_tf["GET /cloudAccounts/aws/assumeRole/externalId"]
        write_tf["POST or PATCH /cloudAccounts"]
    end

    aws_provider --> member_role
    ext_id --> external_tf
    org_ds --> org_api
    org_ds --> member_role
    ext_id --> org_ds
    org_ds --> fwd_resource
    credential_mode --> fwd_resource
    fwd_resource --> write_tf

    classDef neutral fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A;
    classDef fwdnode fill:#E6F1FB,stroke:#185FA5,color:#042C53;
    classDef awsnode fill:#E1F5EE,stroke:#0F6E56,color:#04342C;

    class aws_provider,ext_id,org_ds,credential_mode,fwd_resource neutral;
    class org_api,member_role awsnode;
    class external_tf,write_tf fwdnode;
```

---

## Optional Terraform Bootstrap For CLI Fallback

Terraform can also prepare AWS access before `awssync discover-org` runs. Use this when you need CLI-generated manual JSON files or a break-glass create payload instead of the native provider-managed Forward setup.

```mermaid
flowchart TB
    tf["Terraform"]
    org_role["AWS Organizations read role\nDescribeOrganization, ListAccounts, ListParents"]
    stackset["CloudFormation StackSet\nForward collection role in member accounts"]
    gha["GitHub OIDC role\noptional automation runner"]
    discover["awssync discover-org\nwrites onboarding JSON or POSTs new setup"]

    tf --> org_role
    tf --> stackset
    tf --> gha
    org_role --> discover
    stackset --> discover
    gha --> discover

    classDef neutral fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A;
    classDef awsnode fill:#E1F5EE,stroke:#0F6E56,color:#04342C;

    class tf,discover neutral;
    class org_role,stackset,gha awsnode;
```

---

## Mode 4 — Webhook Daemon

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

## AWS Credential Modes

For existing setup sync and webhook sync, `awssync` does not connect to AWS. The following two modes describe how **Forward** connects to AWS. Both end in `sts:AssumeRole` per member account.

For `discover-org`, `awssync` also uses AWS credentials locally to read AWS Organizations. Those discovery credentials are not written to Forward. Static-key Forward collection requires separate collector key material if the create payload will be posted.

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
| `GET /cloudAccounts/aws/assumeRole/externalId` | Fetch Forward-generated AWS external ID for onboarding | read cloud account setup metadata |
| `POST /cloudAccounts` | Create a new AWS setup from `discover-org --post` | write cloud accounts |
| `GET /snapshots/latestProcessed` | Check snapshot age | read snapshots |
| `POST /webhooks` | Register webhook | manage webhooks |

### awssync → AWS Organizations (`discover-org` only)

| API call | Purpose |
| --- | --- |
| `organizations:DescribeOrganization` | Verify the credentials can see an AWS Organization and get the management account ID |
| `organizations:ListAccounts` | Build the account list for the Forward setup |
| `organizations:ListParents` | Record parent/root or OU evidence per account |

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

- Existing setup sync and webhook sync do not connect to AWS; they use Forward NQE data.
- `discover-org` connects to AWS Organizations only for initial onboarding. It does not write the discovery credentials to Forward.
- The payload JSON is **always written to disk before any PATCH** — changes can be reviewed before or instead of applying.
- `discover-org` writes both onboarding JSON files before any optional `POST /cloudAccounts`.
- Static-key collector secrets are only included in the create payload when explicitly supplied. Without the secret, the file contains a placeholder and is marked not POST-ready.
- Removals require explicit `--allow-removals` flag; `awssync` will not silently
  remove accounts from a Forward setup.
- Webhook receiver is protected by HTTP Basic Auth with a shared secret
  independent of Forward user credentials.

For the full operational procedure see
[AWS Account Sync Procedure](aws-account-sync-procedure.md).
