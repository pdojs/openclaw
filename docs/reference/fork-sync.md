# Fork Sync Policy (Curated Upstream Pull)

This fork intentionally diverges from upstream and should not use blind `git pull` into `main`.

Use a curated sync workflow backed by:

- `config/fork/fork-map.json` (source-of-truth map for divergence + sync classification rules)
- `scripts/fork-gh-pull.sh` (classification helper for upstream changes)

## Why

The fork owns custom structure and conventions (for example config centralization and deploy layout). A blind merge/rebase can silently overwrite these choices or cause expensive conflict churn.

## Workflow

1. Ensure clean working tree.
2. Run:

```bash
scripts/fork-gh-pull.sh [upstream-remote] [base-branch]
```

Defaults:

- remote: `openclaw`
- branch: `main`

3. Review classified upstream file changes.
4. Apply selected updates via cherry-pick or manual replay.
5. Verify:

```bash
pnpm tsgo
pnpm check
```

## Rule

- Do not run direct `git pull upstream/main` on long-lived fork branches.
- Always classify and curate using the fork map first.
