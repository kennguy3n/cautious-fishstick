package access

import (
	"errors"
	"fmt"
)

// Request lifecycle state machine. Mirrors the FSM pattern used in
// uneycom/ztna-business-layer/internal/state_machine/: states are plain
// string constants, transitions are an explicit allow-list, and the public
// entry point is a single Transition(from, to) error helper that consults
// that allow-list.
//
// The state machine is pure logic — no DB dependency, no goroutine, no
// observability hooks. AccessRequestService is responsible for reading the
// current state from the DB, calling Transition to validate, then writing
// the new state back inside a transaction together with an
// access_request_state_history row.

// RequestState is a typed alias for the values stored in
// AccessRequest.State. Strings (not iota) so they round-trip through the DB
// and JSON without translation tables.
type RequestState = string

// Request lifecycle states. The values match models.RequestState* — the
// constants are duplicated here so the state machine has no dependency on
// the models package (avoids an import cycle and keeps this file pure).
const (
	StateRequested       RequestState = "requested"
	StateApproved        RequestState = "approved"
	StateDenied          RequestState = "denied"
	StateCancelled       RequestState = "cancelled"
	StateProvisioning    RequestState = "provisioning"
	StateProvisioned     RequestState = "provisioned"
	StateProvisionFailed RequestState = "provision_failed"
	StateActive          RequestState = "active"
	StateRevoked         RequestState = "revoked"
	StateExpired         RequestState = "expired"
)

// ErrInvalidStateTransition is returned by Transition when the requested
// (from, to) pair is not in the allow-list. Callers wrap this with
// fmt.Errorf("...: %w", err) and surface it as a 4xx validation error.
var ErrInvalidStateTransition = errors.New("access: invalid request state transition")

// allowedTransitions is the source of truth for the request lifecycle FSM.
// Keys are "from" states; values are the set of legal "to" states.
//
// Lifecycle (per docs/internal/PHASES.md Phase 2 + docs/architecture.md §4):
//
//	requested        → approved | denied | cancelled
//	approved         → provisioning | cancelled
//	provisioning     → provisioned | provision_failed
//	provision_failed → provisioning              (operator-initiated retry)
//	provisioned      → active
//	active           → revoked | expired
//
// Terminal states (no outgoing edges): denied, cancelled, revoked, expired.
// Adding a new state means a new constant above and a new entry here; the
// table-driven tests in request_state_machine_test.go pick it up.
var allowedTransitions = map[RequestState]map[RequestState]struct{}{
	StateRequested: {
		StateApproved:  {},
		StateDenied:    {},
		StateCancelled: {},
	},
	StateApproved: {
		StateProvisioning: {},
		StateCancelled:    {},
	},
	StateProvisioning: {
		StateProvisioned:     {},
		StateProvisionFailed: {},
	},
	StateProvisionFailed: {
		StateProvisioning: {},
	},
	StateProvisioned: {
		StateActive: {},
	},
	StateActive: {
		StateRevoked: {},
		StateExpired: {},
	},
	// Terminal states deliberately have no entry — IsTerminalState reports
	// them by absence.
}

// Transition validates whether a request may move from `from` to `to`.
// Returns nil iff the transition is in the allow-list. The error returned
// for an illegal transition wraps ErrInvalidStateTransition with a
// human-readable detail; callers can errors.Is the sentinel without
// caring about the message.
//
// Transition does NOT mutate any DB state. It is the FSM gate; the caller
// is responsible for everything else (reading current state, writing new
// state, recording history).
func Transition(from, to RequestState) error {
	allowed, ok := allowedTransitions[from]
	if !ok {
		// Either an unknown state or a terminal state — both mean "no
		// outgoing transitions".
		return fmt.Errorf("%w: %q is terminal or unknown (cannot move to %q)", ErrInvalidStateTransition, from, to)
	}
	if _, ok := allowed[to]; !ok {
		return fmt.Errorf("%w: %q → %q is not allowed", ErrInvalidStateTransition, from, to)
	}
	return nil
}

// IsTerminalState reports whether `s` has no outgoing transitions. Useful
// for callers that want to short-circuit ("don't bother trying to cancel a
// denied request") before talking to the DB.
func IsTerminalState(s RequestState) bool {
	_, ok := allowedTransitions[s]
	return !ok
}

// AllowedNextStates returns the legal "to" states from `from`. The slice
// is freshly allocated — callers may mutate it. Returns an empty slice for
// terminal or unknown states.
//
// Intended for diagnostics endpoints and admin-UI tooltips ("this request
// can be: approved / denied / cancelled"). Production code paths should
// call Transition directly.
func AllowedNextStates(from RequestState) []RequestState {
	allowed, ok := allowedTransitions[from]
	if !ok {
		return nil
	}
	out := make([]RequestState, 0, len(allowed))
	for s := range allowed {
		out = append(out, s)
	}
	return out
}
