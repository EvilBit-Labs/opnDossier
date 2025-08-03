package processor

import (
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/validator"
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

// validate performs comprehensive validation of the OPNsense configuration using both
// go-playground/validator struct tags and custom validation checks.
func (p *CoreProcessor) validate(cfg *model.OpnSenseDocument) []ValidationError {
	// Pre-allocate errors slice with reasonable capacity
	const initialErrorCapacity = 10

	errors := make([]ValidationError, 0, initialErrorCapacity)

	// Phase 1: Use go-playground/validator for struct tag validation
	if err := p.validator.Struct(cfg); err != nil {
		// Convert validator errors to our ValidationError format
		// Note: go-playground/validator errors can be complex, so we simplify them
		errors = append(errors, ValidationError{
			Field:   "configuration",
			Message: "struct validation failed: " + err.Error(),
		})
	}

	// Phase 2: Use existing custom validation logic
	customErrors := validator.ValidateOpnSenseDocument(cfg)
	for _, customErr := range customErrors {
		errors = append(errors, ValidationError{
			Field:   customErr.Field,
			Message: customErr.Message,
		})
	}

	return errors
}
