# Contributing

## Changes

Open a focused pull request with tests and documentation for operator-visible behavior. Run the same checks used by CI before publishing:

```bash
make ci
```

Keep destructive behavior opt-in, preserve dry-run output, and add regression tests for safety checks. Never include customer credentials, tenant data, generated payloads, or private communications in commits, issues, test fixtures, or workflow logs.

## Attribution

Commits and pull requests must identify the human authors responsible for the change. Automation and generative tools are tools, not contributors: do not add tool identities through `Author`, `Co-authored-by`, contributor lists, acknowledgements, or similar attribution metadata.

Use a verified human email address for commits. Maintainers may ask for attribution metadata to be corrected before merge.
