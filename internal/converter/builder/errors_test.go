package builder

import (
	"errors"
	"testing"
)

func TestErrNilOpnSenseDocument(t *testing.T) {
	t.Parallel()

	// Test that the error has the expected message
	expectedMsg := "input OpnSenseDocument struct is nil"
	if ErrNilOpnSenseDocument.Error() != expectedMsg {
		t.Errorf("ErrNilOpnSenseDocument.Error() = %q, want %q", ErrNilOpnSenseDocument.Error(), expectedMsg)
	}

	// Test that errors.Is works correctly
	testErr := ErrNilOpnSenseDocument
	if !errors.Is(testErr, ErrNilOpnSenseDocument) {
		t.Error("errors.Is should return true for ErrNilOpnSenseDocument")
	}

	// Test that it doesn't match other errors
	otherErr := errors.New("different error")
	if errors.Is(otherErr, ErrNilOpnSenseDocument) {
		t.Error("errors.Is should return false for different error")
	}
}

func TestErrorPropagation(t *testing.T) {
	t.Parallel()

	// Test that wrapped errors still match
	wrappedErr := errors.Join(ErrNilOpnSenseDocument, errors.New("additional context"))
	if !errors.Is(wrappedErr, ErrNilOpnSenseDocument) {
		t.Error("errors.Is should return true for wrapped ErrNilOpnSenseDocument")
	}
}
