package infisical

import (
	"fmt"
	"net/http"
)

// APIError is a non-2xx response from the Infisical API. StatusCode lets the KSP map the
// failure to the right Windows NTE_* code (for example 403 -> access denied).
type APIError struct {
	Operation  string
	StatusCode int
	Message    string
	Code       string
}

const ErrorCodeApprovalRequired = "ApprovalRequired"

func (e *APIError) IsApprovalRequired() bool {
	return e.StatusCode == http.StatusForbidden && e.Code == ErrorCodeApprovalRequired
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

type ApprovalRequestOpenedError struct {
	Err       error
	RequestID string
	Status    string
}

func (e *ApprovalRequestOpenedError) Error() string {
	return fmt.Sprintf("%s (approval request %s is %s)", e.Err.Error(), e.RequestID, e.Status)
}

func (e *ApprovalRequestOpenedError) Unwrap() error { return e.Err }

type ApprovalRequestFailedError struct {
	Err        error
	RequestErr error
}

func (e *ApprovalRequestFailedError) Error() string {
	return fmt.Sprintf("%s (opening an approval request also failed: %v)", e.Err.Error(), e.RequestErr)
}

func (e *ApprovalRequestFailedError) Unwrap() error { return e.Err }
