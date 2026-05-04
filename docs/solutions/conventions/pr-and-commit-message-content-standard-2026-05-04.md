---
title: PR body and commit message content standard — factual record of the change
category: conventions
date: '2026-05-04'
tags:
  - pr-body
  - commit-message
  - ai-disclosure
  - ai-policy
  - convention
  - git-workflow
  - reviewer-experience
component: development-workflow
severity: medium
applies_when:
  - Authoring a pull request body for any branch in this repository
  - Writing the body of a non-trivial commit message
  - Adding the AI disclosure section required by AI_POLICY.md
  - Citing validation or testing steps in any public artifact (PR, commit, changelog, release notes)
related_issues: []
related_docs:
  - docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md
---

# PR Body and Commit Message Content Standard

## Context

Pull request bodies and non-trivial commit messages are the durable public record of what changed in this repository. They are the primary thing a future maintainer reads when triaging a regression, the primary thing a contributor reads when learning the codebase, and the primary thing a reviewer reads when deciding whether to merge.

That gives them a specific job. They are not session logs. They are not a chronicle of the process the author followed to produce the diff. They are a factual statement about what the change does, why it exists, and how it was verified — written so a reader who was not present at authorship time can answer those three questions on their own.

When PR bodies and commit messages drift from that job — when they describe the workflow used to author the change rather than the change itself — two things go wrong. First, the reader is left without the information they actually needed: they cannot reproduce the verification, they cannot tell which behavior changed, and they cannot trace the rationale. Second, every PR that narrates its own production process subtly turns the public record into marketing copy for whatever toolchain produced it. For an open-source project whose timeline is public, that compounds into an erosion of project identity.

This convention captures the standard the project expects from every PR and commit message, regardless of who or what produced the diff.

## Guidance

A PR body and a commit message body — when one is present — should answer three questions for the reader:

1. **What changed?** Describe the diff in code or product terms. Name the files, the behavior, the contract. Reference the ticket, the issue, the prior PR. If the change has multiple commits, a brief commit-by-commit summary is helpful when the order matters.
2. **Why did it change?** Cite the motivating ticket, the bug report, the design decision, the upstream constraint, the user-facing problem. Avoid hand-waving — a reviewer should be able to evaluate whether the change is in scope.
3. **How was it verified?** Name the actual commands a human can run to reproduce the verification. Test runs, lints, benchmarks, smoke tests, manual QA steps — all are fine. The bar is reproducibility by any reader, not the author.

Acceptable verification commands look like the project's own toolchain:

```text
just ci-check
go test -race ./...
golangci-lint run
gh pr checks
pre-commit run -a
```

Anything a human can paste into a shell and run.

What does not belong in a PR body or commit message:

- The name of any tool, agent, or workflow that was used to produce the diff (skill names, plugin names, agent identifiers, automation framework names).
- Counts of automated review rounds, persona votes, consensus thresholds, or pass numbers ("Pass 1: 5-reviewer consensus", "Pass 2: 3-agent second-opinion").
- Paths to local working artifacts (run-artifact paths under `/tmp/`, transcripts, draft files in `.compound-engineering/`, planning notes in `docs/plans/` if those are gitignored, todo numbers from gitignored todo files).
- Iteration counts produced by the authoring workflow ("after 3 fix iterations resolving 8 review findings").
- "Code review" sections that narrate which automated reviewers found which issues, rather than describing what the diff does.

These are local working state. They cannot be reproduced or verified by a human reading the PR. They do not help the reader decide whether to merge. Replace them with the change description and verification commands the reader actually needs.

### AI disclosure

If AI assistance was used in producing the diff, this project's [`AI_POLICY.md`](../../../AI_POLICY.md) requires a disclosure section in the PR body. Keep it minimal and factual:

```markdown
## AI disclosure

Used Claude Code (`<model name>`) for <one-line description of where AI assisted>. All code reviewed locally and via CI before push. Followed process per [`AI_POLICY.md`](../blob/main/AI_POLICY.md).
```

The disclosure satisfies the policy requirement in two short lines. Do not expand it into a skill inventory, a list of automated reviewers, or a description of the agent's workflow — that is the same chronicling problem moved into a different section.

### Pre-merge content checklist

Before opening or updating a PR (or pushing a non-trivial commit), the following should be true. This checklist is what reviewers should expect to see and what authors should self-audit before requesting review.

- [ ] The body answers what changed, why, and how it was verified.
- [ ] Verification steps cite actual shell commands a human reader can run.
- [ ] No tool, agent, skill, plugin, or automation framework names appear anywhere in the body or commit messages.
- [ ] No paths to local working artifacts (`/tmp/...`, gitignored files, draft notes) appear.
- [ ] No persona counts, pass numbers, consensus framing, or iteration tallies appear.
- [ ] If AI assistance was used, the AI disclosure section is present, minimal, and matches the template above.
- [ ] Commit message bodies (if present) describe the why of the change, not the process used to produce it.

## Why This Matters

**Reader value.** PRs and commit messages are read by humans making decisions — reviewers approving merges, on-call engineers tracing regressions, contributors learning the codebase. Those readers do not have access to the original authoring session. Content that only makes sense in that session's context (workflow steps, intermediate artifacts, named automation) is noise to every subsequent reader. Content that describes the change itself helps every subsequent reader.

**Durable artifact value.** PRs and commit messages are indexed, archived, and surface in `git log`, `git blame`, and the GitHub timeline for the project's lifetime. Anything in them that is local to one moment of authorship — a `/tmp/` path, a session number, a count of review rounds — is dead text the moment the session ends. The change description and the verification commands remain useful indefinitely.

**Project identity.** This is an open-source project. Every PR that lands on the public timeline contributes to the project's identity in the eyes of contributors who arrive later. PRs that read like product demos for whatever toolchain produced them turn the project's record into a marketing surface for that toolchain. PRs that describe what the project does and how it stays correct turn the project's record into a record of the project. The latter is what the project's PRs are for; the [`AI_POLICY.md`](../../../AI_POLICY.md) disclosure exists to give AI involvement appropriate, bounded acknowledgment without taking over the artifact.

## When to Apply

Every PR opened against this repository, regardless of size, scope, or whether AI was involved in production. Every commit pushed, regardless of whether it is a one-liner or a large refactor.

There are no carve-outs based on PR size. A trivial dependency bump still gets read by a human reviewer; a large refactor still ends up in `git log`. A draft PR still appears on the public timeline.

The AI disclosure section stays minimal regardless of how much AI assistance was involved in producing the diff. A larger PR does not justify a more elaborate AI section — it justifies a more thorough description of what the diff actually does.

## Examples

### A "Code review" section is a smell

**Drop sections like this from PR bodies:**

```markdown
## Code review

- **Pass 1:** Multi-agent automated review (correctness, testing, maintainability,
  project-standards, performance — 5 reviewers, autofix mode) returned 5/5
  cross-reviewer consensus on hoisting `require.Len` out of `b.Loop()`. All 5
  findings applied as autofixes in `1b0b40e`.
- **Pass 2:** Second-opinion review via `/pr-review-toolkit:review-pr` (3 agents
  — code-reviewer, pr-test-analyzer, comment-analyzer). Caught a doc-accuracy
  error the 5-reviewer pass missed plus an important `b.SetBytes` semantic
  mismatch. All 3 critical/important findings applied in `8f52903`.
```

The section names tools, counts personas, and chronicles the production workflow. None of it helps a reader decide whether to merge or understand what changed. The actual outputs of those review passes — the corrections — are already visible in the diff and the commit messages. The section adds no information beyond that and reads like an automation case study.

**The replacement is no section at all.** The commits already describe what changed; the diff already shows it; the test plan already lists the verification commands.

### Run-artifact paths are local

**Drop lines like this:**

```markdown
Verified with `just ci-check`. Run artifact at `/tmp/compound-engineering/ce-code-review/2026-05-03T22:38:08/`.
```

**Replace with the verification command alone:**

```markdown
Verified with `just ci-check`.
```

A `/tmp/` path is not addressable by anyone who is not the original author and not still in the same shell session. Citing it in a public artifact is dead weight.

### AI disclosure trimmed

**Drop expansions like this:**

```markdown
## AI disclosure

Used Claude Code with the following skills: `ce-compound`, `ce-code-review`,
`ce-commit-push-pr`, `pr-review-toolkit`. Multi-persona code review (5 reviewers)
plus second-opinion pass (3 agents). All findings triaged and resolved before
push. Run artifacts retained at `/tmp/compound-engineering/...`.
```

**Use the minimal form:**

```markdown
## AI disclosure

Used Claude Code (`Claude Opus 4.7 (1M Context)`) for the implementation and
PR description. All code reviewed locally and via CI before push. Followed
process per [`AI_POLICY.md`](../blob/main/AI_POLICY.md).
```

The minimal form satisfies the disclosure requirement in [`AI_POLICY.md`](../../../AI_POLICY.md) while staying out of the way of the actual change description.

### Strong PR body shape

A PR body that meets this standard tends to look like:

```markdown
## Summary

[1–2 paragraphs: what changed, why, and the high-level approach.]

## Acceptance criteria

- [x] [Checkbox per criterion, with evidence — file paths, commands, or short
      descriptions of what was done.]

## Out of scope

- [Anything explicitly not done in this PR, with a one-line reason or a
  follow-up reference.]

## Test plan

- [x] `just ci-check` — passes
- [x] `go test -race ./...` — passes
- [x] [Any benchmarks, smoke tests, manual QA, or other reproducible
      verification steps.]

## AI disclosure

Used Claude Code (`<model>`) for <scope>. All code reviewed locally and via
CI before push. Followed process per [`AI_POLICY.md`](../blob/main/AI_POLICY.md).

## Refs

- Jira: TICKET-NN
- GitHub issue: #NNN
- Related: PR #NNN
```

Every section answers a reader question. No section narrates the author's process.

## See Also

- [`AI_POLICY.md`](../../../AI_POLICY.md) — the project's AI usage policy and disclosure requirement.
- [`AGENTS.md`](../../../AGENTS.md) "Rules of Engagement" — the AI disclosure example phrasing in the agent contributor guide.
- [`docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md`](../logic-errors/documentation-code-drift-interface-refactoring.md) — adjacent learning about AI-generated documentation that drifts from the code it describes; same family of "agent-produced text needs verification against the project's reality" concern, applied to in-code documentation rather than PR bodies.
