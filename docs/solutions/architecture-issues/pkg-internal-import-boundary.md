---
title: Fixing pkg/ importing internal/ packages
category: architecture-issues
date: 2026-03-16
tags: [go, public-api, dependency-injection, interface, pkg-boundary]
components: [pkg/parser, pkg/schema/opnsense]
related_issues: ['#301']
---

## Problem

After moving packages from `internal/` to `pkg/` to create a public API (issue #301), four production files in `pkg/` still imported `internal/` packages. Go enforces the `internal/` access boundary at the module level -- any external consumer running `go get` would get a build error:

```text
use of internal package github.com/EvilBit-Labs/opnDossier/internal/cfgparser not allowed
```

Affected files:

- `pkg/parser/factory.go` -- imported `internal/cfgparser` for `DefaultMaxInputSize`
- `pkg/parser/opnsense/parser.go` -- imported `internal/cfgparser` for `NewXMLParser()`
- `pkg/schema/opnsense/common.go` -- imported `internal/constants` for `NetworkAny`
- `pkg/schema/opnsense/security.go` -- imported `internal/constants` for `NetworkAny`

## Root Cause

The move from `internal/` to `pkg/` was mechanical (import path updates) but did not address structural dependencies. `cfgparser` depends on `internal/validator` which depends on `internal/constants`, so moving the whole chain would cascade across the codebase.

## Solution

Two separate fixes for the two dependency chains:

### 1. Trivial constant extraction (constants.NetworkAny)

Defined `const NetworkAny = "any"` locally in `pkg/schema/opnsense/constants.go` and removed the `internal/constants` import. The internal package keeps its own copy -- both are independent definitions of the same string literal.

### 2. Interface injection for XML parser (cfgparser.XMLParser)

Instead of moving `cfgparser` to `pkg/` (which would cascade into `validator` and `constants`), defined an `XMLDecoder` interface in `pkg/parser/`:

```go
// pkg/parser/factory.go
type XMLDecoder interface {
    Parse(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
    ParseAndValidate(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
}

func NewFactory(decoder XMLDecoder) *Factory {
    return &Factory{xmlDecoder: decoder}
}
```

The `Parser` in `pkg/parser/opnsense/` uses a local unexported interface (Go structural typing satisfies it):

```go
// pkg/parser/opnsense/parser.go
type xmlDecoder interface {
    Parse(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
    ParseAndValidate(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
}

func NewParser(decoder xmlDecoder) *Parser {
    return &Parser{decoder: decoder}
}
```

Application code wires the concrete implementation:

```go
// cmd/convert.go (and other cmd/ files)
factory := parser.NewFactory(cfgparser.NewXMLParser())
```

### 3. Unexport Converter (bonus API surface reduction)

Renamed `Converter` to `converter` (unexported) since `Parser` is the intended entry point. Added `ConvertDocument()` as a convenience function for consumers who have a pre-parsed `OpnSenseDocument`.

## Prevention

- Before exposing `internal/` packages as `pkg/`, run: `grep -rn 'internal/' --include='*.go' pkg/ | grep -v _test.go` to catch boundary violations.
- Consider adding a CI check or linter rule that flags `internal/` imports from `pkg/` production code.
- When a `pkg/` package needs functionality from `internal/`, prefer interface injection over moving entire dependency chains.
- Test files in `pkg/` *can* import `internal/` (Go allows this) -- only production code is restricted for external consumers.
