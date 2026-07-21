---
title: Memoizing recursive graph resolution must also bound output size
category: performance-issues
date: '2026-07-20'
tags:
  - recursion
  - memoization
  - dag
  - dos
  - named-objects
  - alias-resolution
  - untrusted-input
  - firewall
severity: high
components:
  - pkg/model/named_objects.go
related_issues:
  - '#202'
related_docs: []
---

# Memoizing Recursive Graph Resolution Must Also Bound Output Size

> **Fix status:** Introduced by [PR #696](https://github.com/EvilBit-Labs/opnDossier/pull/696) (firewall rule shadowing detection), unmerged as of this writing. The cited file `pkg/model/named_objects.go` does not exist on `main` yet — it is added by that PR. The behavior described below reflects that PR's `NamedObjects.Resolve` / `resolveNode` implementation.

## Problem

`NamedObjects.Resolve` flattens a firewall alias to its member set by recursively expanding nested alias references. A cycle guard (a visited-path set) prevented infinite loops, but nothing bounded a **non-cyclic** graph. A diamond/DAG-shaped alias graph — where several nodes reference the same child alias — re-expanded the shared subtree once per reference, blowing up exponentially. Because `opnDossier` ingests attacker-supplyable `config.xml` files and the shadow detector calls `Resolve` synchronously per rule pair, a sub-1KB config could hang the whole analysis run (a denial of service).

## Symptoms

- A shadow-detection or analysis run hangs indefinitely on a config with heavily nested aliases; CPU pinned, no output, no crash.
- Reproduced in-session: 14 alias levels, each referencing the next level 8 times (~a few hundred bytes of alias definitions, well under any input-size cap), did not complete in over 20 seconds. The naive call count is `8^14 ≈ 4.4e12`.

## What Didn't Work

**Adding memoization on computation alone did not fix it.** The intuitive fix was a per-`Resolve` memo cache keyed by alias name, so a shared subtree is *computed* once instead of re-expanded per reference. That is correct and necessary — but the run still hung.

Empirical bisection was what exposed the real cause: with only the memo, resolution completed instantly for `levels <= 8` but still timed out at `levels >= 10`. If memoization were the whole story, `8^8` (~16.7M) and `8^14` would behave the same way (both instant). They didn't. The memo bounded *how many times each node is computed*, but not *how large each node's result is*.

The root cause: each level concatenates N copies of its child's already-expanded member slice (`members = append(members, subMembers...)`), so the **slice itself** grows multiplicatively with depth — `a0`'s pre-dedup member slice held `8^levels` entries. The final top-level dedup collapsed it to one entry, but *building* that slice was an exponential-size allocation and copy. Memoizing computation does nothing about exponential *output size*.

## Solution

Two changes to `resolveNode` / `Resolve` (in the PR #696 version of `pkg/model/named_objects.go`), which together make resolution linear in both time and allocation:

1. **Memoize clean expansions per `Resolve` call.** A `memo map[string][]string`, checked at the top of `resolveNode` and written only when a node resolved cleanly (`resolved == true`). Cycle/depth-cap failures are path-dependent and must **not** be cached — a name that failed via a cycle on one branch may resolve cleanly on another.

2. **Dedupe at every node, not just at the top.** Member sets are a *set* (a value reached via two paths counts once), so deduping the accumulated members at each node is semantically identical to deduping once at the end — but it also bounds each level's slice to its distinct-member count. For the pathological DAG (all paths collapse to one literal), every node's deduped set is size 1, so the whole graph resolves in `O(levels * fanout)`.

```go
// Both are needed. Memo alone leaves the exponential-SIZE blowup; dedup
// alone leaves the exponential-COUNT recomputation.
members = dedupeSorted(members) // bounds slice size at each node
if resolved {
    memo[name] = members // bounds recomputation of shared subtrees
}
```

A related safety valve landed in the containment predicate (`internal/analysis/overlap.go`, same PR): an alias that resolves to more than a generous cap (`maxResolvedMembers`) is treated as opaque (`aliasBlocked`) rather than expanded, bounding the separate `O(n*m)` address/port containment cross-product on hostile input.

## Why This Works

The two axes of blowup are independent and both must be bounded:

- **Computation count** — how many times each node is expanded. Bounded by the memo (a shared subtree is expanded once per `Resolve`, not once per reference path).
- **Output size** — how many entries each expansion produces. Bounded by per-node dedup (a node's result is its distinct-member count, which cannot exceed the total distinct literals in the graph).

Memoization is the reflexive answer to "recursive function is slow," and it is correct here — but it silently addresses only the first axis. When the *result* of a recursive call is itself a collection that gets concatenated up the call stack, the output can be exponential even when computation is memoized. The dedup is what collapses the set-union up the tree.

## Prevention

- **When memoizing a recursive function that returns a collection, ask whether the collection can grow exponentially up the call stack.** Bound the output (dedup/normalize at each node), not just the recomputation. A cycle guard prevents infinite loops; it does not prevent DAG-shaped exponential fan-out.
- **Treat any recursive resolution over attacker-supplyable input as a DoS surface.** `opnDossier` parses untrusted `config.xml`; anything that walks a user-defined reference graph (alias resolution, group expansion, include chains) needs a depth cap, a cycle guard, *and* a size/output bound — all three.
- **Pin the pathological case with a regression test that fails on timeout, not on correctness.** The DAG regression (`TestNamedObjects_Resolve_DAGDoesNotBlowUp` in PR #696) resolves in a goroutine with a `select` on a short timeout, asserting completion — a purely correctness-based assertion would pass on the buggy code (it does eventually return the right members) and never catch the blowup.
- **When a "should be linear" fix still isn't fast, bisect the input size rather than re-reading the code.** The size cliff (fast at `n=8`, hung at `n=10`) was the signal that the memo was working on one axis and not the other; reading the code alone kept confirming the memo "looked correct."
