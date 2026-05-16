package gateway

// This file is intentionally a thin alias surface for the
// gateway's credential-injection helpers. The production
// implementation (APISecretInjector) and the SecretInjector
// interface both live in api_client.go alongside the
// SessionAuthorizer, because they share the same HTTP plumbing
// (base URL, API key, http.Client). Keeping a dedicated
// secret_injector.go matches the task list in
// docs/pam/progress.md and makes the file easy to locate when
// future milestones (K8s exec, DB token issuance) add new injector
// implementations.
//
// The fallback contract is documented here:
//
//   1. The SSH listener first attempts SSH-CA authentication
//      against the upstream target. If the gateway is configured
//      with an SSH CA *and* the target trusts the CA's public
//      key, the SSH cert path completes without ever touching the
//      injector.
//
//   2. When the CA is unavailable (target does not trust the CA,
//      or PAM_GATEWAY_SSH_CA_KEY was unset) the listener calls
//      SecretInjector.InjectSecret to fetch the decrypted
//      credential for the session's account. The credential is
//      held only in memory for the lifetime of the upstream
//      connection.
//
//   3. After the upstream session ends, the listener drops the
//      injector return value and lets the Go runtime reclaim the
//      backing byte slice. The injector itself never persists
//      anything to disk.
//
// Anything new here must keep the "never persist" invariant.
