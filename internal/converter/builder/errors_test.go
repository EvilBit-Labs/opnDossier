package builder

import (
	"errors"
	"testing"
)

func TestErrNilDevice(t *testing.T) {
	t.Parallel()

	// Test that the error has the expected message
	expectedMsg := "device configuration is nil"
	if ErrNilDevice.Error() != expectedMsg {
		t.Errorf("ErrNilDevice.Error() = %q, want %q", ErrNilDevice.Error(), expectedMsg)
	}

	// Test that errors.Is works correctly
	testErr := ErrNilDevice
	if !errors.Is(testErr, ErrNilDevice) {
		t.Error("errors.Is should return true for ErrNilDevice")
	}

	// Test that it doesn't match other errors
	otherErr := errors.New("different error")
	if errors.Is(otherErr, ErrNilDevice) {
		t.Error("errors.Is should return false for different error")
	}
}

func TestErrorPropagation(t *testing.T) {
	t.Parallel()

	// Test that wrapped errors still match
	wrappedErr := errors.Join(ErrNilDevice, errors.New("additional context"))
	if !errors.Is(wrappedErr, ErrNilDevice) {
		t.Error("errors.Is should return true for wrapped ErrNilDevice")
	}
}
