---
title: The served model reference is hand-maintained; `just generate-docs` writes a different file
date: '2026-10-17'
category: workflow-issues
module: docs/data-model, tools/docgen, justfile
problem_type: workflow_issue
component: development-workflow
severity: medium
applies_when:
  - Adding, renaming, or removing a field on a `pkg/model` type and deciding which documentation to update
  - A plan or checklist says to run `just generate-docs` to refresh `docs/data-model/model-reference.md`
  - '`just generate-docs` changes `docs/templates/model-reference.md` and the diff does not show the type you changed'
  - Deciding whether a documentation page's "auto-generated, do not edit" banner can be trusted
tags:
  - documentation-drift
  - generated-docs
  - model-reference
  - api-snapshot
  - docgen
  - justfile
  - mkdocs
---

# The served model reference is hand-maintained; `just generate-docs` writes a different file

## Context

`docs/data-model/model-reference.md` is the page mkdocs serves as "Model Reference" (`mkdocs.yml:109`). It opens with a banner saying it is auto-generated and should be regenerated with `just generate-docs` (`docs/data-model/model-reference.md:3`). The banner is wrong. The `generate-docs` recipe (`justfile:357-358`) runs `tools/docgen/main.go`, whose default output is `docs/templates/model-reference.md` (`tools/docgen/main.go:20`), a different tracked file that mkdocs does not serve and that carries no `InboundNATRule` section at all. The served page is hand-maintained, and it had already fallen behind the model before anyone noticed: its port-forward table omitted `IPProtocol`, `Priority`, `Tag`, and `Tagged`.

The trap has two faces. In the #881 work, the agent regenerated the templates page after adding fields to `InboundNATRule`, grepped it for the type, found nothing, and concluded the model reference needed no update (session history). The served page stayed stale. In the follow-up branch for #899, the plan said to run `just generate-docs` to refresh the served page; the document review caught that the recipe would leave the named file untouched and churn the unrelated templates file, and the plan was corrected to a hand edit. An agent memory note carried into both sessions repeated the banner's claim and was wrong for the same reason.

## Guidance

When a change touches a `pkg/model` type, treat these as two separate artifacts with two separate update paths:

- **`pkg/parser/testdata/api-snapshots/pkg-model.golden`** is the artifact that is genuinely regenerated. Refresh it with the `-update` form of `TestPublicAPISnapshot` under `mise exec` (never bare `go`), then read the diff: it should contain exactly the fields you added and nothing else.
- **`docs/data-model/model-reference.md`** is edited by hand, in the same commit as the model change. Add or change the rows in the table for that type, mirroring the wording of the neighbouring rows. Do not run `just generate-docs` for this; the recipe cannot produce the edit.

Do not trust a page's "auto-generated" banner as proof of its provenance. Check what the named generator actually writes (`grep -n defaultOutputFile tools/docgen/main.go`, or read the recipe) and whether that output is the file the site serves (`grep -n <page> mkdocs.yml`). A banner without a `Generated: <timestamp>` line is a hint that nothing has written the file in a long time; the templates page carries one, the served page does not.

The banner itself was left in place by the #899 branch, because fixing the generator-to-page relationship is its own decision: either point docgen's default output at the served page and make it emit every model type, or drop the banner and keep the page hand-maintained. Until one of those lands, the hand edit is the correct action.

## Why This Matters

A contributor who trusts the banner runs the recipe, sees `docs/templates/model-reference.md` change, commits that, and leaves the served page stale, or concludes the generator is broken. Either way the page that `docs/for-agents.md:54` links as the `CommonDevice` schema for the JSON and YAML exports silently drifts from the model. That line repeats the same "auto-generated from the Go struct definitions" claim, so the banner's error is stated in two places. The templates page is regenerated routinely (its recent history is a run of parser PRs), which makes the drift look maintained. The failure never shows up in CI: `TestPublicAPISnapshot` guards the Go surface, not the documentation page.

## When to Apply

- Any change to a struct under `pkg/model` that adds, renames, or removes an exported field.
- Any plan, checklist, or review comment that says "regenerate the model reference".
- Any time a documentation page's banner names a generator: verify the generator's output path and the site's nav entry before relying on it.

## Examples

Adding two fields to the port-forward model, as the #899 branch did:

```text
# Regenerated artifact (public API surface)
mise exec -- go test ./pkg/parser/... -run TestPublicAPISnapshot -update
git diff --stat pkg/parser/testdata/api-snapshots/   # exactly the new fields

# Hand-maintained artifact (served documentation)
# edit docs/data-model/model-reference.md, table "InboundNATRule (Port Forward)":
| `Category` | `string` | `nat.inboundRules[].category` | Classification category |
| `PoolOpts` | `string` | `nat.inboundRules[].poolOpts`  | Address pool options    |
```

What not to do, from the #881 session: run `just generate-docs`, grep `docs/templates/model-reference.md` for the type, find no section, and conclude the documentation is already correct. The absence of the section is why the grep looked clean, and it is also why the served page is never updated automatically.

## Related

- `docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md`: the same family of defect (documentation asserting facts about code that drifted) and the same prevention, verify claims against the executable source of truth and update docs in the same commit.
- `docs/solutions/workflow-issues/dependency-bump-markdown-output-whitespace-drift.md`: the regenerate-and-read-the-diff discipline for golden fixtures that this learning applies to the API snapshot.
- `docs/solutions/workflow-issues/just-ci-check-enforces-more-than-ci.md`: covers `TestPublicAPISnapshot` diffing `go doc` output against its golden fixture.
- `docs/development/public-api.md`: a new struct field is a minor, non-breaking change, which is why the snapshot diff is reviewed rather than blocked.
