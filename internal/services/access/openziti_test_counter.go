package access

import "sync/atomic"

// openZitiCallCounterValue is a process-global counter that tracks the
// number of times PolicyService.Promote (or any future Phase 3 code in
// this repo) reaches out to OpenZiti.
//
// Phase 3 in this repository deliberately does NOT integrate with
// OpenZiti — that integration lives in the ZTNA business layer. The
// counter is exposed so a test (TestPromote_DoesNotInvokeOpenZiti)
// can assert the negative: drafts and their promote leg here must
// never increment this counter. The day someone wires OpenZiti into
// PolicyService.Promote, they must:
//
//  1. Bump the counter inside the new code path.
//  2. Update TestPromote_DoesNotInvokeOpenZiti to either delete the
//     assertion or rewrite it to count the expected number of calls.
//  3. Update docs/PHASES.md so the exit criterion checkbox state
//     matches reality.
//
// Defining the counter as a package-level atomic keeps the test free
// of any mock or wiring; the assertion is a single integer
// comparison.
var openZitiCallCounterValue atomic.Int64

// openZitiCallCount returns the current counter value. Tests use this
// to assert "OpenZiti was called zero times during my flow". The
// counter is reset by resetOpenZitiCallCounter — tests should call
// that helper at the top of any test that asserts counter behaviour.
func openZitiCallCount() int64 {
	return openZitiCallCounterValue.Load()
}

// resetOpenZitiCallCounter zeroes the counter. Always call this at
// the top of any test that subsequently asserts openZitiCallCount(),
// because the counter is process-global and other tests may
// (eventually) increment it.
func resetOpenZitiCallCounter() {
	openZitiCallCounterValue.Store(0)
}
