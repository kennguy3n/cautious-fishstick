package access

import (
	"errors"
	"sort"
	"testing"
)

// TestTransition_AllValidTransitionsSucceed asserts every edge in the FSM's
// allow-list returns nil from Transition. The expected list is hard-coded
// (rather than reflecting on allowedTransitions) so the test is a real
// regression check: if someone deletes an edge from the allow-list this
// test fails.
func TestTransition_AllValidTransitionsSucceed(t *testing.T) {
	valid := []struct{ from, to RequestState }{
		{StateRequested, StateApproved},
		{StateRequested, StateDenied},
		{StateRequested, StateCancelled},
		{StateApproved, StateProvisioning},
		{StateApproved, StateCancelled},
		{StateProvisioning, StateProvisioned},
		{StateProvisioning, StateProvisionFailed},
		{StateProvisionFailed, StateProvisioning},
		{StateProvisioned, StateActive},
		{StateActive, StateRevoked},
		{StateActive, StateExpired},
	}
	for _, tc := range valid {
		t.Run(tc.from+"->"+tc.to, func(t *testing.T) {
			if err := Transition(tc.from, tc.to); err != nil {
				t.Errorf("Transition(%q,%q) returned error %v; want nil", tc.from, tc.to, err)
			}
		})
	}
}

// TestTransition_IllegalEdgesReturnError covers a representative selection
// of disallowed (from, to) pairs. Each one wraps ErrInvalidStateTransition
// so callers can errors.Is regardless of the message format.
func TestTransition_IllegalEdgesReturnError(t *testing.T) {
	bad := []struct{ from, to RequestState }{
		// Skipping intermediate states.
		{StateRequested, StateActive},
		{StateRequested, StateProvisioning},
		// Wrong direction.
		{StateApproved, StateRequested},
		// Unrelated jumps.
		{StateProvisioning, StateActive},
		{StateProvisioned, StateRevoked},
		// Resurrecting from a terminal state.
		{StateDenied, StateApproved},
		{StateCancelled, StateProvisioning},
		{StateRevoked, StateActive},
		{StateExpired, StateActive},
		// Unknown source state.
		{"banana", StateApproved},
	}
	for _, tc := range bad {
		t.Run(tc.from+"->"+tc.to, func(t *testing.T) {
			err := Transition(tc.from, tc.to)
			if err == nil {
				t.Fatalf("Transition(%q,%q) returned nil; want error", tc.from, tc.to)
			}
			if !errors.Is(err, ErrInvalidStateTransition) {
				t.Errorf("Transition(%q,%q) error = %v; want it to wrap ErrInvalidStateTransition", tc.from, tc.to, err)
			}
		})
	}
}

// TestIsTerminalState pins the four terminal states and ensures every
// non-terminal state in the FSM is reported correctly. Adding a new
// terminal state requires adding it here too.
func TestIsTerminalState(t *testing.T) {
	terminal := []RequestState{StateDenied, StateCancelled, StateRevoked, StateExpired}
	for _, s := range terminal {
		if !IsTerminalState(s) {
			t.Errorf("IsTerminalState(%q) = false; want true", s)
		}
	}
	nonTerminal := []RequestState{
		StateRequested, StateApproved, StateProvisioning,
		StateProvisioned, StateProvisionFailed, StateActive,
	}
	for _, s := range nonTerminal {
		if IsTerminalState(s) {
			t.Errorf("IsTerminalState(%q) = true; want false", s)
		}
	}
}

// TestIsTerminalState_HasNoOutgoingTransitions cross-checks: any state
// flagged terminal must also fail Transition for every conceivable target.
// This is the "no zombie edges" invariant.
func TestTerminalStates_HaveNoOutgoingTransitions(t *testing.T) {
	allStates := []RequestState{
		StateRequested, StateApproved, StateDenied, StateCancelled,
		StateProvisioning, StateProvisioned, StateProvisionFailed,
		StateActive, StateRevoked, StateExpired,
	}
	for _, s := range allStates {
		if !IsTerminalState(s) {
			continue
		}
		for _, target := range allStates {
			if err := Transition(s, target); err == nil {
				t.Errorf("terminal state %q allowed transition to %q; want error", s, target)
			}
		}
	}
}

// TestAllowedNextStates_MatchesTransitionAllowList ensures the diagnostic
// helper agrees with Transition. We sort both sides so the test is order-
// independent.
func TestAllowedNextStates_MatchesTransitionAllowList(t *testing.T) {
	cases := map[RequestState][]RequestState{
		StateRequested:       {StateApproved, StateCancelled, StateDenied},
		StateApproved:        {StateCancelled, StateProvisioning},
		StateProvisioning:    {StateProvisionFailed, StateProvisioned},
		StateProvisionFailed: {StateProvisioning},
		StateProvisioned:     {StateActive},
		StateActive:          {StateExpired, StateRevoked},
	}
	for from, want := range cases {
		got := AllowedNextStates(from)
		sort.Strings(got)
		// want is already sorted in the literal above.
		if len(got) != len(want) {
			t.Errorf("AllowedNextStates(%q) = %v; want %v", from, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("AllowedNextStates(%q)[%d] = %q; want %q", from, i, got[i], want[i])
			}
		}
	}
	// Every terminal state returns an empty slice.
	for _, s := range []RequestState{StateDenied, StateCancelled, StateRevoked, StateExpired} {
		if got := AllowedNextStates(s); len(got) != 0 {
			t.Errorf("AllowedNextStates(%q) = %v; want empty (terminal)", s, got)
		}
	}
}
