package infisical

import "fmt"

// APIError is a non-2xx response from the Infisical API. StatusCode lets the KSP map the
// failure to the right Windows NTE_* code (for example 403 -> access denied).
type APIError struct {
	Operation  string
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s failed: HTTP %d: %s", e.Operation, e.StatusCode, e.Message)
}

// RequestError is a transport-level failure (DNS, connection, timeout) with no HTTP status.
type RequestError struct {
	Operation string
	Err       error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%s failed: %v", e.Operation, e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }
