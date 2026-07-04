---
title: CI runs on pull_request, not on feature-branch pushes
category: workflow-issues
date: '2026-07-04'
problem_type: workflow_issue
component: development-workflow
severity: low
tags:
  - github-actions
  - ci
  - workflow-triggers
  - pull-request
  - just-ci-check
  - branch-workflow
applies_when:
  - Pushing a feature branch and expecting GitHub Actions to run
  - Monitoring CI after a push and finding zero workflow runs for the commit
  - Wondering why the github-action-monitor skill reports no runs on a branch push
related_issues: []
related_docs: []
---

# CI runs on `pull_request`, not on feature-branch pushes

## Context

After pushing a feature branch, the post-push CI monitor searched for workflow runs on the pushed commit and found **zero**. The instinct is to suspect a broken push, a misconfigured workflow, or a queuing delay. None of those was true — the workflows are simply not configured to run on a branch push. Remote CI only started once a pull request was opened.

## Guidance

opnDossier's CI is gated on `pull_request` and `push` to `main`. **A push to a feature branch with no open PR triggers nothing.** To exercise remote CI on a branch, open a PR — that fires `ci.yml` and `security.yml` against the head commit.

The local `just ci-check` recipe is the pre-push gate; remote CI is a **PR-time** gate. Running `just ci-check` locally before pushing is what validates a branch commit — not a remote run, because there is no remote run until the PR exists.

Trigger map for the workflows in `.github/workflows/` (as of this writing):

| Workflow         | Triggers on                                                           |
| ---------------- | --------------------------------------------------------------------- |
| `ci.yml`         | `push: main`, `pull_request`                                          |
| `security.yml`   | `push: main`, `pull_request`, weekly schedule                         |
| `benchmarks.yml` | `push: main`, `pull_request` (filtered to `**.go`, `go.{mod,sum}`)    |
| `docs.yml`       | `push: main`                                                          |
| `go-deps.yml`    | `push: main`                                                          |
| `scorecard.yml`  | `push: main`, `branch_protection_rule`, schedule, `workflow_dispatch` |
| `release.yml`    | `push` tags `v*`, `workflow_dispatch`                                 |
| `sbom.yml`       | schedule, `workflow_dispatch`                                         |

Practical consequence: on a feature branch, **only a PR (or merging to `main`) runs Actions.** Doc/metadata-only branches still get the full `ci.yml` + `security.yml` matrix once a PR is open, because neither has a path filter.

## Why This Matters

- The `github-action-monitor` skill returning "0 runs for this commit" on a branch push is **expected**, not a failure. Reporting it as a CI failure would be wrong; reporting it as "CI passed" would be equally wrong — nothing ran.
- It prevents wasted debugging: the absence of runs is a trigger-config fact, not a symptom of a bad push, auth problem, or Actions outage.
- It reinforces the project rule that `just ci-check` must pass **locally before pushing** — it is the real gate for branch commits, and there is no remote substitute until PR time. (See AGENTS.md § "Run `just ci-check` BEFORE committing".)

## When to Apply

- Immediately after `git push` of a feature branch, before concluding anything about CI health.
- When the CI monitor reports no runs — check whether a PR exists before investigating the push.
- When deciding whether to open a PR: opening one is the action that starts remote CI, so open it (or keep the branch local) deliberately rather than waiting for runs that will never appear.

## Examples

Finding zero runs on a fresh branch push is the normal state:

```bash
# After: git push -u origin chore/my-branch  (no PR yet)
COMMIT=$(git rev-parse HEAD)
gh run list --branch chore/my-branch --limit 10 \
  --json headSha,name,status \
  --jq "[.[] | select(.headSha==\"$COMMIT\")] | length"
# => 0     ← expected; no PR means no pull_request trigger, and the
#             push trigger only fires on main
```

Opening the PR is what starts CI:

```bash
gh pr create --base main --head chore/my-branch --title "..." --body-file body.md
# Now ci.yml + security.yml queue against the head commit:
gh run list --branch chore/my-branch --limit 10 \
  --json name,status,event \
  --jq '[.[] | select(.event=="pull_request") | {name,status}]'
# => CI: in_progress, Security: in_progress
```
