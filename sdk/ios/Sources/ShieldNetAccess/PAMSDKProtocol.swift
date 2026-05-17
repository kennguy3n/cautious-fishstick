//
// PAMSDKProtocol.swift — PAM extension of the iOS Access SDK contract.
//
// The PAM surface bolts on top of `AccessSDKClient` rather than
// extending it: a host application that doesn't enable Privileged
// Access Management can stay on the access-only protocol and keep
// its dependency surface small. Apps that ship PAM features adopt
// `PAMSDKClient` alongside the access protocol.
//
// REST endpoint mapping (per `docs/pam/architecture.md` §6 and
// `docs/pam/proposal.md`):
//
//   approveLease       → POST /pam/leases/:id/approve
//   denyLease          → POST /pam/leases/:id/revoke
//   revealSecret       → POST /pam/secrets/:id/reveal
//
// Push notification parsing (`parseApprovalNotification(userInfo:)`)
// is a pure function — no I/O, no `URLSession` — so it can be unit
// tested without a network mock and called from inside an
// `UNNotificationServiceExtension` if the host app wants to render a
// rich confirm-the-number prompt.
//
// There is **no on-device inference** in this SDK. The same rule
// the access surface enforces applies here.
//

import Foundation

/// Async REST surface for PAM-specific operations that the mobile
/// approver (the human tapping the push) needs to drive.
///
/// All methods return throwing values typed against `AccessSDKError`
/// so consumers can branch on transport / auth / decoding failures
/// the same way they do for the access surface.
public protocol PAMSDKClient: Sendable {
    /// Parse a PAM approval push payload out of the `userInfo`
    /// dictionary delivered by `UNUserNotificationCenter` (APNS) or
    /// the Firebase Messaging data dict.
    ///
    /// This method is intentionally synchronous and pure — it does
    /// no I/O. Errors:
    ///   - `.invalidInput` if the payload is missing required keys
    ///     or carries an unexpected `type` discriminator.
    ///   - `.decoding` if a sub-field can't be coerced into the
    ///     expected type (e.g. `risk_score` not in {low,medium,high}).
    func parseApprovalNotification(
        userInfo: [AnyHashable: Any]
    ) throws -> PAMApprovalNotification

    /// Verify that the digit string the user tapped matches the
    /// real `matched_code` from the notification, in constant time.
    ///
    /// Returns `.matched` only if the strings are byte-identical;
    /// any difference (including length) returns `.mismatched`. The
    /// SDK uses this to short-circuit the approve flow client-side
    /// when the user picks one of the decoy codes — the server
    /// performs the same check, but failing fast saves a network
    /// round-trip and gives the user a clear UX signal.
    func verifyMatchedCode(
        selected: String,
        notification: PAMApprovalNotification
    ) -> NumberMatchOutcome

    /// Approve a pending lease.
    ///
    /// `POST /pam/leases/:id/approve` — body `{ workspace_id,
    /// approver_id, duration_minutes }`. The host app passes the
    /// `notification` it parsed earlier so the SDK can stamp the
    /// matched code into the body for server-side double-check
    /// (when the server adds the matched-code gate the SDK already
    /// sends the right field; otherwise the server simply ignores
    /// it).
    ///
    /// `selectedCode` must match `notification.matchedCode` byte-for-
    /// byte. The SDK throws `.invalidInput` immediately if not, so
    /// callers must not skip the `verifyMatchedCode` step.
    func approveLease(
        notification: PAMApprovalNotification,
        approverUserID: String,
        durationMinutes: Int?,
        selectedCode: String
    ) async throws -> PAMLease

    /// Deny a pending lease (mapped onto the existing revoke
    /// endpoint).
    ///
    /// `POST /pam/leases/:id/revoke` — body `{ workspace_id,
    /// reason }`. Denial does not require number matching because
    /// the worst-case outcome is a false negative (the requester
    /// re-submits); skipping number matching keeps the "reject"
    /// flow one tap.
    func denyLease(
        notification: PAMApprovalNotification,
        reason: String
    ) async throws -> PAMLease

    /// Reveal a vaulted secret after a passkey step-up assertion.
    ///
    /// `POST /pam/secrets/:id/reveal` — body `{ workspace_id,
    /// user_id, mfa_assertion }`. `mfaAssertion` is the
    /// JSON-encoded `PassKeyAssertion` produced by
    /// `ASAuthorizationController` on the host side. The SDK
    /// serialises it into the `mfa_assertion` field so the
    /// server-side `MFAVerifier` can unwrap and verify the
    /// assertion against the user's enrolled public-key
    /// credential.
    func revealSecret(
        secretID: String,
        workspaceID: String,
        userID: String,
        assertion: PassKeyAssertion
    ) async throws -> PAMSecretRevealResponse
}
