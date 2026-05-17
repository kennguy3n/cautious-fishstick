// PAMSDKClient.kt — PAM extension of the Android Access SDK contract.
//
// The PAM surface bolts on top of `AccessSDKClient` rather than
// extending it: a host application that doesn't enable Privileged
// Access Management can stay on the access-only interface and keep
// its dependency surface small. Apps that ship PAM features
// implement `PAMSDKClient` alongside the access interface.
//
// REST endpoint mapping (per `docs/pam/architecture.md` §6 and
// `docs/pam/proposal.md`):
//
//   approveLease       → POST /pam/leases/:id/approve
//   denyLease          → POST /pam/leases/:id/revoke
//   revealSecret       → POST /pam/secrets/:id/reveal
//
// Push notification parsing (`parseApprovalNotification(data)`) is
// a pure function — no I/O, no `OkHttpClient` — so it can be unit
// tested without a network mock and called from a
// `FirebaseMessagingService.onMessageReceived` callback.
//
// There is **no on-device inference** in this SDK. The same rule
// the access surface enforces applies here.

package com.shieldnet360.access

/**
 * Async REST surface for PAM-specific operations that the mobile
 * approver (the human tapping the push) needs to drive.
 *
 * Methods are declared `suspend` so concrete implementations (e.g.
 * an `OkHttpPAMSDKClient`) can do their I/O on coroutine
 * dispatchers supplied by the host application. Errors are
 * surfaced as [AccessSDKException].
 */
interface PAMSDKClient {
    /**
     * Parse a PAM approval push payload out of the `data` map
     * delivered by Firebase Cloud Messaging
     * (`RemoteMessage.getData()`).
     *
     * This method is intentionally synchronous and pure — it does
     * no I/O. Throws:
     *   - [AccessSDKException.InvalidInput] if the payload is
     *     missing required keys or carries an unexpected `type`
     *     discriminator.
     *   - [AccessSDKException.Decoding] if a sub-field can't be
     *     coerced into the expected type (e.g. `risk_score` not in
     *     {low,medium,high}).
     */
    fun parseApprovalNotification(data: Map<String, String>): PAMApprovalNotification

    /**
     * Verify that the digit string the user tapped matches the
     * real `matched_code` from the notification, in constant time.
     *
     * Returns `MATCHED` only if the strings are byte-identical;
     * any difference (including length) returns `MISMATCHED`. The
     * SDK uses this to short-circuit the approve flow client-side
     * when the user picks one of the decoy codes — the server
     * performs the same check, but failing fast saves a network
     * round-trip and gives the user a clear UX signal.
     */
    fun verifyMatchedCode(
        selected: String,
        notification: PAMApprovalNotification,
    ): NumberMatchOutcome

    /**
     * Approve a pending lease.
     *
     * `POST /pam/leases/:id/approve` — body `{ workspace_id,
     * approver_id, duration_minutes, matched_code }`. The
     * `notification` carries the immutable lease id / workspace
     * id; the SDK stamps the matched code into the body for
     * server-side double-check.
     *
     * `selectedCode` must match `notification.matchedCode`
     * byte-for-byte. The SDK throws
     * [AccessSDKException.InvalidInput] immediately if not, so
     * callers must not skip the `verifyMatchedCode` step.
     */
    suspend fun approveLease(
        notification: PAMApprovalNotification,
        approverUserId: String,
        durationMinutes: Int? = null,
        selectedCode: String,
    ): PAMLease

    /**
     * Deny a pending lease (mapped onto the existing revoke
     * endpoint).
     *
     * `POST /pam/leases/:id/revoke` — body `{ workspace_id,
     * reason }`. Denial does not require number matching because
     * the worst-case outcome is a false negative (the requester
     * re-submits); skipping number matching keeps the "reject"
     * flow one tap.
     */
    suspend fun denyLease(
        notification: PAMApprovalNotification,
        reason: String,
    ): PAMLease

    /**
     * Reveal a vaulted secret after a passkey step-up assertion.
     *
     * `POST /pam/secrets/:id/reveal` — body `{ workspace_id,
     * user_id, mfa_assertion }`. `assertion` is the
     * [PassKeyAssertion] produced by the host application's
     * `androidx.credentials.CredentialManager` flow. The SDK
     * serialises it into the `mfa_assertion` field as a JSON
     * string so the server-side `MFAVerifier` can unwrap and
     * verify the assertion against the user's enrolled public-key
     * credential.
     */
    suspend fun revealSecret(
        secretId: String,
        workspaceId: String,
        userId: String,
        assertion: PassKeyAssertion,
    ): PAMSecretRevealResponse
}
