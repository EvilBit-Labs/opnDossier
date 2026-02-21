package processor

import (
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// ValidationError represents a validation error with field and message information.
type ValidationError struct {
	Field   string
	Message string
}

// Error implements the error interface for ValidationError.
func (e ValidationError) Error() string {
	return e.Message
}

// validate performs comprehensive validation of the device configuration using
// go-playground/validator struct tags.
//
//nolint:nonamedreturns // named return required for defer/recover to append panic errors
func (p *CoreProcessor) validate(cfg *common.CommonDevice) (errors []ValidationError) {
	// Pre-allocate errors slice with reasonable capacity
	const initialErrorCapacity = 10

	errors = make([]ValidationError, 0, initialErrorCapacity)

	// Wrap the validator call in a recover block so any panic from unexpected
	// input is captured as a ValidationError rather than crashing the pipeline.
	defer func() {
		if r := recover(); r != nil {
			errors = append(errors, ValidationError{
				Field:   "configuration",
				Message: fmt.Sprintf("struct validation panicked: %v", r),
			})
		}
	}()

	// Use go-playground/validator for struct tag validation
	if err := p.validator.Struct(cfg); err != nil {
		// Convert validator errors to our ValidationError format
		// Note: go-playground/validator errors can be complex, so we simplify them
		errors = append(errors, ValidationError{
			Field:   "configuration",
			Message: "struct validation failed: " + err.Error(),
		})
	}

	return errors
}
