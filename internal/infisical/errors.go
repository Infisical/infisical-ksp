package infisical

import (
	"errors"
	"fmt"
	"net/http"
)

// APIError is a non-2xx response from the Infisical API. StatusCode lets the KSP map the
// failure to the right Windows NTE_* code (for example 403 -> access denied).
type APIError struct {
	Operation         string
	StatusCode        int
	Message           string
	Code              string
	HasPendingRequest bool
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

type ApprovalRequestPendingError struct {
	Err error
}

func (e *ApprovalRequestPendingError) Error() string {
	return fmt.Sprintf("%s (an approval request is already awaiting review)", e.Err.Error())
}

func (e *ApprovalRequestPendingError) Unwrap() error { return e.Err }

type ApprovalNotConfiguredError struct {
	Err error
}

func (e *ApprovalNotConfiguredError) Error() string {
	return fmt.Sprintf("%s (no approval block is configured, so no request was opened)", e.Err.Error())
}

func (e *ApprovalNotConfiguredError) Unwrap() error { return e.Err }

func IsApprovalOutcome(err error) bool {
	var opened *ApprovalRequestOpenedError
	var pending *ApprovalRequestPendingError
	var notConfigured *ApprovalNotConfiguredError
	var failed *ApprovalRequestFailedError
	return errors.As(err, &opened) || errors.As(err, &pending) ||
		errors.As(err, &notConfigured) || errors.As(err, &failed)
}

type ApprovalRequestFailedError struct {
	Err        error
	RequestErr error
}

func (e *ApprovalRequestFailedError) Error() string {
	return fmt.Sprintf("%s (opening an approval request also failed: %v)", e.Err.Error(), e.RequestErr)
}

func (e *ApprovalRequestFailedError) Unwrap() error { return e.Err }
