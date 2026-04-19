# CLI Output Policy

opnDossier's CLI emits output through several distinct channels. Each channel has a clear purpose and a canonical API. When adding new output, pick the channel that matches the purpose — not the nearest convenient tool.

The structured-logger-for-everything default is *not* the policy. A user-facing warning about a trust-model caveat and a debug trace of XML token inspection look very different to an operator, and they belong on different channels. Reaching for `fmt.Fprintf(os.Stderr, ...)` or `logger.Warn` because it is the nearest import is the pattern this document exists to replace.

## Channels

### 1. User-facing structured messages

**Purpose.** Warnings, informational notices, or non-fatal errors shown to the human operator as part of normal CLI behaviour. These are UX-bearing messages — the reader is a person, not a machine.

**Canonical API.** A small internal messenger — planned as `internal/cliui/` — that wraps `charmbracelet/lipgloss` for styling and falls back to plain text on `TERM=dumb` or when stderr is not a TTY. Until that helper exists, continue to use `charmbracelet/log` at `Warn`/`Info` level with a message that reads well to an operator (not a log-parser).

**Rules.**

- Must be TTY-aware and must honour `TERM=dumb` by degrading to plain ASCII.
- Must respect verbosity flags (for example, `--quiet` suppresses informational messages; warnings are not suppressed by log level).
- Writes to stderr, never stdout — stdout is reserved for machine-readable output.
- Never emits ANSI escape codes when stderr is not a TTY.

**Examples.** The `--plugin-dir` trust-model warning emitted from `cmd/audit.go`; the "wrap-width too wide for terminal" notice in `cmd/shared_flags.go`; the sanitizer's "output file already exists, use `--force` to overwrite" notice.

### 2. Diagnostic / troubleshooting output

**Purpose.** Debug and trace output that helps a developer or operator diagnose unexpected behaviour. The audience is someone who explicitly opted in via `--verbose` or an elevated log level.

**Canonical API.** `logging.Logger` at `Debug` or `Trace` level (`internal/logging/`), with structured fields for context.

**Rules.**

- Gated by `--verbose` / `--log-level` / configured log level. Not visible by default.
- Prefer structured fields (`logger.Debug("loaded plugin", "name", name, "path", path)`) over preformatted strings — downstream log processors benefit from the structure.
- Never write diagnostic output to stdout.
- Do not use this channel for anything the operator needs to see under normal conditions. If it matters by default, it belongs in Channel 1.

**Examples.** Plugin-load detail (which `.so` files were discovered, which registered successfully); XML token inspection during parser debugging; request/response tracing inside the audit pipeline.

### 3. Interactive prompts

**Purpose.** Questions and confirmations that require the user to type or select something before the command can proceed.

**Canonical API.** Direct stdin/stdout via a small prompt helper — `charmbracelet/huh` if a richer form UI is warranted, or `bufio.Scanner` on `os.Stdin` for single-line y/n prompts. Prompts are never suppressed by log level.

**Rules.**

- Must go to a TTY. If stdin is not a TTY, the command must fail fast with a clear error — never silently block waiting for input that will never arrive.
- Prompt text is written to stderr (so it does not contaminate machine-readable stdout when a command's primary output is on stdout).
- Never suppressed by `--quiet` or log level. If the command needs input, the user must see the prompt.
- Automation paths should have a non-interactive equivalent: an explicit flag (`--force`, `--yes`) or an environment variable that answers the prompt.

**Examples.** Overwrite confirmation when `convert --output <path>` would clobber an existing file; destructive-operation confirmation in `config validate --fix`.

### 4. Machine-readable output

**Purpose.** Output consumed by other programs — CI pipelines, jq-style processing, integration scripts. Selected explicitly via flags like `--format json`, `--format yaml`, or `--json`.

**Canonical API.** Direct writes to stdout via `encoding/json`, `yaml.v3`, or the equivalent structured encoder. The schema is part of the command's contract and must be versioned and documented.

**Rules.**

- **Stdout only.** Nothing unrelated to the machine-readable payload may contaminate stdout in this mode — not logs, not progress indicators, not human-readable headers, not a trailing "done!" message.
- **No escape codes** — no ANSI colour, no styled output.
- All other channels (user-facing warnings, diagnostics, prompts, progress) must go to stderr while this mode is active so parsers see a clean stdout.
- Errors in this mode should still produce a parseable error document on stdout when possible, with a non-zero exit code; free-form human error text goes to stderr.

**Examples.** `audit --format json` emitting a structured report; `convert --format yaml` emitting the CommonDevice model.

### 5. Progress / status

**Purpose.** Indication that a long-running operation is making progress — multi-file audit runs, large XML parses, plugin compilation.

**Canonical API.** `charmbracelet/bubbles/progress` on a TTY; plain text fallback (`"Processing file 3/12..."` periodically or once per major phase) on non-TTY, `TERM=dumb`, or when running in CI.

**Rules.**

- Must gracefully degrade on non-TTY, `TERM=dumb`, and CI environments. A spinner that needs ANSI cursor moves must detect the environment and fall back to line-oriented text.
- Progress goes to stderr, never stdout.
- Must not appear in machine-readable mode (see Channel 4). Either suppress it entirely, or verify the target is stderr and the operator did not redirect stderr.
- Long-running operations with no progress output are not acceptable for multi-minute workloads — silence reads as "hung."

**Examples.** Multi-file audit processing indicator; the `just docs` build step's phase indicator.

### 6. Pre-logger fallback

**Purpose.** Emit errors that occur before the logger is initialized — configuration parse failures during bootstrap, flag validation errors that fire before `PersistentPreRunE`, panics during early startup.

**Canonical API.** `fmt.Fprintf(os.Stderr, ...)`. This is the **only** sanctioned use of raw `Fprintf` for output.

**Rules.**

- Narrow scope. The pre-logger window is small by design — once the logger is initialized, all subsequent output moves to the appropriate channel above.
- Do not use this channel as a shortcut after the logger is available. If a site has access to the logger or the command context, it belongs on Channel 1 or Channel 2.
- Messages should be short and actionable — the operator cannot filter them by log level.

**Examples.** Error emitted from `cmd/exitcodes.go` when exit-code translation itself fails; `cmd/root.go` config-file-parse-failure fallback; a panic recovery boundary printing a diagnostic before re-raising.

## TTY detection

Use `github.com/mattn/go-isatty` — already a transitive dependency via the Charm stack — or equivalent. Prefer a single helper (e.g., `cmd/output_policy.go` or `internal/cliui/tty.go`) so tests can stub the detection. Do not scatter `isatty.IsTerminal(os.Stderr.Fd())` calls across the codebase; each channel's canonical API should internalize the check.

## TERM=dumb handling

All styled output — `lipgloss`-rendered blocks, `bubbles` progress bars, `glamour`-rendered markdown — must fall back to plain ASCII when `TERM=dumb` is set. This is a project-wide rule, documented in AGENTS.md § Rules of Engagement, and applies to every channel that renders styled content. Automation and CI environments set `TERM=dumb` precisely because they cannot render escape sequences; emitting them anyway corrupts logs and breaks assertions.

## What NEVER goes where

- Stdout never carries log output in `--format json` / `--format yaml` / `--json` mode.
- Stderr never carries machine-readable payload output.
- Log levels never suppress interactive prompts — if a command needs input, the user sees the prompt regardless of `--quiet`.
- ANSI escape codes never appear when stderr (for human output) or stdout (for machine output) is not a TTY, or when `TERM=dumb`.
- Progress indicators never appear inside machine-readable output streams.

## Phase B migration

Per-site triage of the ~30 existing `fmt.Fprintf(os.Stderr, ...)` sites against this policy is tracked separately. Each site will be classified into one of the six channels above, converted to the canonical API for that channel, and documented in the commit message with a reference to the channel number in this document. See todo #163 Phase B and the triage table therein.

Until Phase B completes, existing `Fprintf` sites remain in place — mechanical conversion without policy review is how the current inconsistency accumulated, and doing it again would lock in the same pattern under a different name.
