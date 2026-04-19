package pfsense

import (
	"sync"

	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// ResetValidatorForTesting clears the currently installed validator and
// replaces the sync.Once guard with a fresh instance so subsequent calls to
// [SetValidator] succeed again. It exists solely for in-package regression
// tests that need to exercise [SetValidator]'s one-shot semantics multiple
// times within a single process. Because the helper lives in a _test.go
// file, it is not part of the public API and is not visible to production
// consumers of this package.
//
// Callers MUST serialize their use of this helper with any other goroutines
// that touch [SetValidator] or [Parser.ParseAndValidate] — resetting the
// guard while a peer goroutine is mid-call races by definition.
func ResetValidatorForTesting() {
	setValidatorOnce = sync.Once{}
	validateFuncHolder.Store(nil)
}

// ValidatorForTesting returns the currently installed validator (or nil) so
// tests can assert which function the sync.Once locked in. Lives in a
// _test.go file to keep the accessor out of the public API.
func ValidatorForTesting() func(doc *pfsense.Document) error {
	v := loadValidator()
	if v == nil {
		return nil
	}
	return v
}
