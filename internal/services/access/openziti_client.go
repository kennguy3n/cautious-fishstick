package access

import "context"

// OpenZitiClient is the narrow contract the access-platform service
// layer uses to ask the OpenZiti control plane to disable an identity
// (per docs/architecture.md §8 and docs/architecture.md §13).
//
// Phase 6 wires this contract into JMLService.HandleLeaver: after
// every active grant has been revoked and the user has been removed
// from every Team, the leaver flow calls DisableIdentity so the
// OpenZiti enrolment is taken offline. Phase 6+ may extend the
// interface with EnableIdentity / RevokeIdentityKeys / etc.
//
// The actual OpenZiti integration lives in the ZTNA business layer
// (uneycom/ztna-business-layer); this repo holds only the contract.
// Operators wire a concrete client at boot in cmd/ztna-api by
// instantiating the ZTNA-business-layer adapter and calling
// JMLService.SetOpenZitiClient.
//
// Failure semantics: best-effort. A DisableIdentity error logs but
// does NOT roll back the leaver — by the time the OpenZiti call
// runs, every grant has already been revoked and team memberships
// have been dropped, so the source-of-truth state is already
// "deactivated". The OpenZiti control plane reconciles eventually.
type OpenZitiClient interface {
	// DisableIdentity asks the OpenZiti controller to take the
	// supplied identity offline. userExternalID is the workspace's
	// external user ID — typically the SCIM `id` from the inbound
	// directory.
	DisableIdentity(ctx context.Context, userExternalID string) error
}

// OpenZitiClientFunc is a function adapter that satisfies
// OpenZitiClient. Useful for ad-hoc wiring from cmd/* and for tests
// that want a lambda.
type OpenZitiClientFunc func(ctx context.Context, userExternalID string) error

// DisableIdentity satisfies OpenZitiClient.
func (f OpenZitiClientFunc) DisableIdentity(ctx context.Context, userExternalID string) error {
	return f(ctx, userExternalID)
}
