# opnDossier v1.5.0 — Public Go API lock, secret redaction, and parsing correctness

v1.5.0 locks down the public Go API surface in `pkg/model`, `pkg/schema/*`, and `pkg/parser/*` for cross-repo consumption — sibling products can now depend on opnDossier as a stable library. It also ships a high-severity sanitizer fix for OpenVPN keys, a subtle but pervasive parsing correctness fix, and plugin-loader hardening.

## Highlights

**Public Go API is now stable.** `pkg/model/`, `pkg/schema/opnsense/`, `pkg/schema/pfsense/`, and `pkg/parser/` are audited, fully godoc'd, and frozen for external consumers. You can now import them directly:

```go
import (
    "github.com/EvilBit-Labs/opnDossier/pkg/parser"
    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // register parser
    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
)

doc, _ := parser.NewFactory().Parse(ctx, xmlReader)
```

No more `internal/` imports, stdlib-only production deps, and the blank-import registration pattern follows `database/sql`. (#569, #575, #580, #586)

**OpenVPN TLS-auth keys are now redacted.** Previously, `opnDossier sanitize` on configs containing OpenVPN `<tls>` or `<StaticKeys>` elements **leaked raw HMAC keys to stdout** — enough material to forge OpenVPN handshakes. Path-anchored patterns (`openvpn.tls`, `openvpn.statickeys`) now catch the real OpenVPN paths without false-positives against Suricata IDS or IPsec charon syslog. A new `IsOpenVPNStaticKey` value detector matches the `-----BEGIN OpenVPN Static key V1-----` envelope. (#587)

**Liberal boolean parsing for OPNsense/pfSense.** Previously, `<enable>0</enable>` was treated as enabled because the parser only checked element presence — any non-empty body was "true." Now, boolean elements delegate through a shared truthy vocabulary (`1|on|yes|true|enable|enabled`, case-insensitive), so `<enable>0</enable>`, `<enable>no</enable>`, and `<enable>off</enable>` all correctly resolve to `false`. (#558, #577)

**Dynamic plugin loader preflight.** Before `plugin.Open()` is invoked, the loader now rejects symlinked `.so` files, non-regular files (FIFO/socket/device nodes), group/world-writable plugin files, and world-writable parent directories. Every load attempt emits a structured audit log with SHA-256, mode bits, owner UID, and verdict. The dynamic-plugin trust model is now documented explicitly in `audit` help text. (#587)

## Upgrade notes

**Breaking: template config keys silently ignored.** If your `~/.opnDossier.yaml` or environment set any of the following, they are no longer recognized (Viper ignores them without error):

- Config keys: `template`, `engine`, `use_template`, `export.template`
- Env vars: `OPNDOSSIER_TEMPLATE`, `OPNDOSSIER_ENGINE`, `OPNDOSSIER_EXPORT_TEMPLATE`

The template system was removed in favor of the programmatic builder — remove these keys from your config to avoid confusion. (#550, #556)

**Breaking (Go API consumers only): `pfsense.ValidateFunc` → `pfsense.SetValidator`.** The exported `var ValidateFunc` has been replaced with a `sync.Once`-guarded `SetValidator(fn)` function to prevent malicious plugin `init()` from stomping the validator post-CLI-setup. Migration:

```go
// Before (v1.4.x):
pfsense.ValidateFunc = myValidator

// After (v1.5.0+):
pfsense.SetValidator(myValidator)  // one-shot; first call wins
```

Only affects code that injects a custom pfSense validator — most consumers don't touch this. (#587)

Otherwise: drop-in upgrade from v1.4.0.

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md#150---2026-04-21) for the complete list.
