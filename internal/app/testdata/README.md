# Pre-branch compatibility artifacts

These fixtures were exercised with the binary built from merge base
`0c0dbd5dfb41c8e713a33896b63b969225dcfd50` against a local fake Forward API.

- `pre_branch_apply_plan.json` was emitted by a dry-run of the old binary. Its
  original SHA-256 is
  `da2612db7cbd41071306e6a8d28404d36de74ae98ebb9dd9ecf2c28dfa63738e`.
- `pre_branch_apply_plan.rollback.json` was emitted when that plan was applied
  by the old binary. Its original SHA-256 is
  `804a9a15d5aab5e5b65ff796990d61ad17bc64df9e59fcc3d5fbf385c94565b5`.
- `pre_branch_external_ids.csv` is not an output format: the old binary only
  consumes External ID CSV files. This exact input was accepted by the old
  binary and is retained to verify the historical input contract.

The old JSON writer did not append a final newline. The compatibility test
removes the repository-added final newline before checking the original hash
and invoking the current reader.

The pre-branch webhook server did not persist state, so that binary could not
produce an old webhook-state fixture.
