//go:build deadcode

// This file is gated behind the `deadcode` build tag so that `go test ./...`,
// `just test`, `just test-race`, `just test-coverage`, and CI's ordinary Test
// job never run TestDeadCodeGuard -- this guard runs the full `deadcode`
// RTA analysis, which is far slower than the rest of the package's tests and
// has no reason to run on every `go test ./...` invocation. `just
// deadcode-check` (part of `just ci-check`, and the CI Lint job's
// "Unreachable-symbol guard" step) passes `-tags=deadcode` explicitly.

package internal

// deadcode_test.go is what `just deadcode-check` runs. It fails when
// `deadcode -test=false ./...` reports a function unreachable from the
// shipped binary's call graph that is not exempted in deadcode_allowlist.txt.
//
// This is the recurrence guard for unreachable *symbols* inside otherwise
// reachable packages -- the class TestAllInternalPackagesReachable (in
// security_test.go) does not cover, since a package can be wired into the
// binary while individual exported functions inside it are dead.
//
// `.golangci.yml`'s `unused` linter does not cover this class either: it
// counts a symbol's own _test.go file as a caller, so a function reachable
// only from its own tests reads as live. `deadcode -test=false` excludes
// test files from the call graph, which is exactly the pattern this guard
// targets.
//
// This guard is wired into `just ci-check` and the CI Lint job's
// "Unreachable-symbol guard" step (no `continue-on-error`). It was seeded
// red on purpose (KTD7) when introduced and ran advisory-only until the
// dead-surface cleanup swept the seeded, unexempted surface it was red
// against and every remaining unreachable symbol was either deleted or
// allowlisted with a documented class and reason.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// deadcodeAllowlistPath is the checked-in exemption list, relative to this
// package's directory -- which is the test binary's working directory.
const deadcodeAllowlistPath = "deadcode_allowlist.txt"

// deadcodeTimeout bounds the RTA analysis. It compiles and analyzes the whole
// module, so it is slower than a `go list` probe but still bounded.
const deadcodeTimeout = 3 * time.Minute

// deadcodeAllowlistClasses are the only legitimate exemption classes (KTD3).
// An entry with any other value, or an empty one, is a defect.
//
//nolint:gochecknoglobals // package-level table read by the guard test below
var deadcodeAllowlistClasses = map[string]bool{
	"reflection-dispatched": true,
	"test-time-safety-gate": true,
	"public-surface":        true,
}

// deadcodeSymbol identifies a function by its full package import path plus
// its name ("Receiver.Method" for a method). This is deadcode's own identity
// for a reported function and is stable across code motion within a file,
// unlike a file:line position.
type deadcodeSymbol struct {
	Path string
	Name string
}

func (s deadcodeSymbol) String() string { return s.Path + "." + s.Name }

// deadcodeAllowlistEntry is one parsed line of deadcode_allowlist.txt.
type deadcodeAllowlistEntry struct {
	Symbol deadcodeSymbol
	Class  string
	Reason string
	Line   int // 1-based line number in the allowlist file, for error messages
}

// runDeadcode runs `deadcode -test=false -json ./...` from the module root
// and returns every function it reports unreachable from the binary's call
// graph. A failure here is a broken probe, not a finding -- it fails the
// test loudly rather than reporting an empty result as a clean tree.
func runDeadcode(t *testing.T) []deadcodeSymbol {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), deadcodeTimeout)
	defer cancel()

	// #nosec G204 -- args are test-owned literals, never external input.
	cmd := exec.CommandContext(ctx, "deadcode", "-test=false", "-json", "./...")
	cmd.Dir = ".." // this package's directory is internal/; the module root is its parent.

	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("deadcode failed: %v\n%s", err, stderr.String())
	}

	var report []struct {
		Path  string `json:"Path"`
		Funcs []struct {
			Name string `json:"Name"`
		} `json:"Funcs"`
	}

	if jsonErr := json.Unmarshal(out, &report); jsonErr != nil {
		t.Fatalf("parsing deadcode -json output: %v\n%s", jsonErr, out)
	}

	var symbols []deadcodeSymbol

	for _, pkg := range report {
		for _, fn := range pkg.Funcs {
			symbols = append(symbols, deadcodeSymbol{Path: pkg.Path, Name: fn.Name})
		}
	}

	return symbols
}

// parseDeadcodeAllowlist parses the "<path>|<symbol>|<class>|<reason>" format
// of deadcode_allowlist.txt from sc. Blank lines and lines starting with "#"
// are comments. It is a pure function, kept separate from file I/O, so the
// format's error paths are unit-testable without touching disk.
func parseDeadcodeAllowlist(sc *bufio.Scanner) ([]deadcodeAllowlistEntry, error) {
	var entries []deadcodeAllowlistEntry

	seen := make(map[deadcodeSymbol]bool)
	lineNum := 0

	for sc.Scan() {
		lineNum++

		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.SplitN(line, "|", 4)
		if len(fields) != 4 {
			return nil, &deadcodeAllowlistFormatError{
				Line: lineNum,
				Msg: fmt.Sprintf(
					"expected 4 pipe-delimited fields (path|symbol|class|reason), got %d", len(fields),
				),
			}
		}

		sym := deadcodeSymbol{Path: strings.TrimSpace(fields[0]), Name: strings.TrimSpace(fields[1])}
		if sym.Path == "" || sym.Name == "" {
			return nil, &deadcodeAllowlistFormatError{Line: lineNum, Msg: "path and symbol fields must not be empty"}
		}

		if seen[sym] {
			return nil, &deadcodeAllowlistFormatError{Line: lineNum, Msg: "duplicate entry for " + sym.String()}
		}

		seen[sym] = true

		entries = append(entries, deadcodeAllowlistEntry{
			Symbol: sym,
			Class:  strings.TrimSpace(fields[2]),
			Reason: strings.TrimSpace(fields[3]),
			Line:   lineNum,
		})
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// deadcodeAllowlistFormatError reports a malformed line in the allowlist
// file, with the line number so a contributor can find it immediately.
type deadcodeAllowlistFormatError struct {
	Line int
	Msg  string
}

func (e *deadcodeAllowlistFormatError) Error() string {
	return fmt.Sprintf("%s: line %d: %s", deadcodeAllowlistPath, e.Line, e.Msg)
}

// loadDeadcodeAllowlist reads and parses the checked-in allowlist file.
func loadDeadcodeAllowlist(t *testing.T) []deadcodeAllowlistEntry {
	t.Helper()

	f, err := os.Open(deadcodeAllowlistPath)
	if err != nil {
		t.Fatalf("opening %s: %v", deadcodeAllowlistPath, err)
	}
	defer f.Close()

	entries, err := parseDeadcodeAllowlist(bufio.NewScanner(f))
	if err != nil {
		t.Fatalf("%v", err)
	}

	return entries
}

// deadcodeCheckResult holds every violation of the allowlist invariants
// (R7, R8, R11) for a single deadcode run.
type deadcodeCheckResult struct {
	Unlisted  []deadcodeSymbol         // unreachable symbols with no allowlist entry (R7)
	Stale     []deadcodeAllowlistEntry // entries no longer among the currently-unreachable symbols (R11)
	BadClass  []deadcodeAllowlistEntry // entries with an unrecognized or missing class (R8)
	BadReason []deadcodeAllowlistEntry // entries with no stated reason (R8)
}

// checkDeadcodeAllowlist compares a deadcode run's output against the
// allowlist and returns every violation. It is a pure function, independent
// of both the deadcode binary and the filesystem, so the allowlist-invariant
// logic can be exercised with fabricated inputs.
//
// A stale entry (R11) is one that does not match a symbol in the current
// unreachable set. That covers a genuinely deleted or renamed symbol and a
// symbol that has become reachable identically: both cases call for removing
// the entry, the former because it is meaningless and the latter because
// KTD7 requires each deletion/reachability-fixing unit to clean up its own
// exemptions as it lands.
func checkDeadcodeAllowlist(found []deadcodeSymbol, allowlist []deadcodeAllowlistEntry) deadcodeCheckResult {
	byOwner := make(map[deadcodeSymbol]deadcodeAllowlistEntry, len(allowlist))
	for _, entry := range allowlist {
		byOwner[entry.Symbol] = entry
	}

	var result deadcodeCheckResult

	seen := make(map[deadcodeSymbol]bool, len(found))

	for _, sym := range found {
		seen[sym] = true

		entry, ok := byOwner[sym]
		if !ok {
			result.Unlisted = append(result.Unlisted, sym)
			continue
		}

		if !deadcodeAllowlistClasses[entry.Class] {
			result.BadClass = append(result.BadClass, entry)
		}

		if entry.Reason == "" {
			result.BadReason = append(result.BadReason, entry)
		}
	}

	for _, entry := range allowlist {
		if !seen[entry.Symbol] {
			result.Stale = append(result.Stale, entry)
		}
	}

	sortSymbols(result.Unlisted)
	sortEntries(result.Stale)
	sortEntries(result.BadClass)
	sortEntries(result.BadReason)

	return result
}

func sortSymbols(s []deadcodeSymbol) {
	slices.SortFunc(s, func(a, b deadcodeSymbol) int { return strings.Compare(a.String(), b.String()) })
}

func sortEntries(s []deadcodeAllowlistEntry) {
	slices.SortFunc(s, func(a, b deadcodeAllowlistEntry) int {
		return strings.Compare(a.Symbol.String(), b.Symbol.String())
	})
}

// TestDeadCodeGuard is the guard `just deadcode-check` runs. See the package
// doc comment at the top of this file for what it does and does not enforce
// yet.
func TestDeadCodeGuard(t *testing.T) {
	found := runDeadcode(t)
	if len(found) == 0 {
		t.Fatal("deadcode reported nothing: the probe is broken (or the module has no dead code left, in " +
			"which case delete this guard against an empty result, not the test)")
	}

	allowlist := loadDeadcodeAllowlist(t)
	result := checkDeadcodeAllowlist(found, allowlist)

	for _, entry := range result.BadClass {
		t.Errorf("%s:%d: %s has unrecognized class %q; must be one of reflection-dispatched, "+
			"test-time-safety-gate, public-surface", deadcodeAllowlistPath, entry.Line, entry.Symbol, entry.Class)
	}

	for _, entry := range result.BadReason {
		t.Errorf("%s:%d: %s is exempted with no stated reason", deadcodeAllowlistPath, entry.Line, entry.Symbol)
	}

	for _, entry := range result.Stale {
		t.Errorf("%s:%d: %s is exempted but is not currently unreachable (deleted, renamed, or now "+
			"reachable); remove the stale entry", deadcodeAllowlistPath, entry.Line, entry.Symbol)
	}

	if len(result.Unlisted) > 0 {
		names := make([]string, len(result.Unlisted))
		for i, sym := range result.Unlisted {
			names[i] = sym.String()
		}

		t.Errorf(
			"%d unreachable function(s) are not exempted in %s:\n  %s\n\n"+
				"Each is dead code: nothing in the shipped binary can reach it. Either delete it, wire it "+
				"into a real caller, or add it to %s with its class and reason.",
			len(result.Unlisted), deadcodeAllowlistPath, strings.Join(names, "\n  "), deadcodeAllowlistPath,
		)
	}

	assertValueDetectorsReachable(t, found)
}

// deadcodeValueDetectorSymbols are internal/sanitizer functions that are
// wired into a rule's ValueDetector struct field rather than called
// directly. deadcode's RTA sees a function assigned to a func-typed struct
// field as reachable, so none of these should ever be reported unreachable.
// If one is, an accidentally-unwired redaction detector would read as safe
// to delete, and the guard needs a fourth allowlist class before it can be
// trusted on internal/sanitizer.
//
//nolint:gochecknoglobals // fixed regression set, read only by the test below
var deadcodeValueDetectorSymbols = []string{
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsPrivateKey",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsCertificate",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsEmail",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsPublicIP",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.isPrivateIPv4",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsMAC",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsSubnet",
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer.IsBase64",
}

// assertValueDetectorsReachable is the empirical check named in the plan's
// test scenarios: a detector function stored as a ValueDetector struct-field
// value in internal/sanitizer/rules.go must not appear in deadcode's
// unreachable list.
func assertValueDetectorsReachable(t *testing.T, found []deadcodeSymbol) {
	t.Helper()

	unreachable := make(map[string]bool, len(found))
	for _, sym := range found {
		unreachable[sym.String()] = true
	}

	for _, sym := range deadcodeValueDetectorSymbols {
		if unreachable[sym] {
			t.Errorf("PROMINENT: %s is reported unreachable, but it is wired into a rule's ValueDetector "+
				"field in internal/sanitizer/rules.go, not called directly. deadcode failed to see "+
				"function-value dispatch here, which means the guard cannot be trusted on this package "+
				"without a fourth allowlist class -- stop and report this, do not allowlist it away.", sym)
		}
	}
}
