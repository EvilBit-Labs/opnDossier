package builder

import "errors"

// ErrNilDevice is returned when the input device configuration is nil.
var ErrNilDevice = errors.New("device configuration is nil")
