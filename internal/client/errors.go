package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Reasons of the gate's error answers ({"reason","message","details"}).
const (
	ReasonPrecondition   = "precondition"
	ReasonNotFound       = "not_found"
	ReasonForbidden      = "forbidden"
	ReasonNotOwner       = "not_owner"
	ReasonForeignRRset   = "foreign_rrset"
	ReasonTainted        = "tainted"
	ReasonZoneLocked     = "zone_locked"
	ReasonUpstream       = "upstream"
	ReasonInvalid        = "invalid"
	ReasonTooManyChanges = "too_many_changes"
	ReasonPolicyBusy     = "policy_busy"
)

// ValidationError is one entry of a 400 invalid_policy answer of the
// delegation API.
type ValidationError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// APIError is a non-2xx answer of the gate.
type APIError struct {
	Status  int
	Method  string
	Path    string
	Reason  string
	Message string
	Details json.RawMessage
	Errors  []ValidationError
	Body    string
	// Attempts is the number of requests sent, retries included. A write
	// refused after a retry may have been applied by an earlier attempt.
	Attempts int
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("dns-gate: %s %s: HTTP %d", e.Method, e.Path, e.Status)
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// AsAPIError returns the APIError in err, if any.
func AsAPIError(err error) (*APIError, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Is reports whether err is an APIError with this status (0: any) and reason ("": any).
func Is(err error, status int, reason string) bool {
	e, ok := AsAPIError(err)
	return ok && (status == 0 || e.Status == status) && (reason == "" || e.Reason == reason)
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool { return Is(err, http.StatusNotFound, "") }

// IsPrecondition reports a 412.
func IsPrecondition(err error) bool { return Is(err, http.StatusPreconditionFailed, "") }

// ErrNotGate is returned by Info when the endpoint is not a dns-gate.
var ErrNotGate = errors.New("not a dns-gate: no discovery document at " + InfoPath)
