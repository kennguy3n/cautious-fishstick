package pam

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// newSecretBroker is a tiny test helper that builds a fresh PAM DB
// and wires a SecretBrokerService with the access-platform's
// PassthroughEncryptor — that encryptor round-trips plaintext as a
// no-op so the tests can compare bytes directly.
func newSecretBroker(t *testing.T) (*SecretBrokerService, *bytes.Buffer) {
	t.Helper()
	db := newPAMDB(t)
	svc, err := NewSecretBrokerService(db, access.PassthroughEncryptor{})
	if err != nil {
		t.Fatalf("NewSecretBrokerService: %v", err)
	}
	return svc, &bytes.Buffer{}
}

func TestNewSecretBrokerService_NilEncryptor(t *testing.T) {
	_, err := NewSecretBrokerService(newPAMDB(t), nil)
	if !errors.Is(err, ErrEncryptorRequired) {
		t.Fatalf("err = %v; want ErrEncryptorRequired", err)
	}
}

func TestSecretBroker_VaultSecret_PasswordHappyPath(t *testing.T) {
	svc, _ := newSecretBroker(t)
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("VaultSecret: %v", err)
	}
	if secret.ID == "" {
		t.Fatalf("empty secret id")
	}
	if secret.WorkspaceID != "ws-1" {
		t.Fatalf("workspace = %q", secret.WorkspaceID)
	}
	// The returned struct intentionally has Ciphertext blanked
	// (defence-in-depth, mirrors GetSecretMetadata / RotateSecret).
	// Verify the row was nonetheless persisted with the sealed
	// payload by reading it back from the DB directly.
	var persisted models.PAMSecret
	if err := svc.db.Where("id = ?", secret.ID).First(&persisted).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if persisted.Ciphertext == "" {
		t.Fatalf("ciphertext not persisted")
	}
}

func TestSecretBroker_VaultSecret_SSHKey(t *testing.T) {
	svc, _ := newSecretBroker(t)
	pem := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "ssh_key",
		Plaintext:  pem,
	})
	if err != nil {
		t.Fatalf("VaultSecret ssh_key: %v", err)
	}
	if secret.SecretType != "ssh_key" {
		t.Fatalf("type = %q; want ssh_key", secret.SecretType)
	}
}

func TestSecretBroker_VaultSecret_Validation(t *testing.T) {
	svc, _ := newSecretBroker(t)
	cases := []struct {
		name        string
		workspaceID string
		in          VaultSecretInput
	}{
		{"missing workspace", "", VaultSecretInput{SecretType: "password", Plaintext: []byte("p")}},
		{"missing secret_type", "ws-1", VaultSecretInput{Plaintext: []byte("p")}},
		{"invalid secret_type", "ws-1", VaultSecretInput{SecretType: "unknown", Plaintext: []byte("p")}},
		{"missing plaintext", "ws-1", VaultSecretInput{SecretType: "password"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.VaultSecret(context.Background(), tc.workspaceID, tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v; want ErrValidation", err)
			}
		})
	}
}

func TestSecretBroker_GetSecretMetadata_DoesNotLeakCiphertext(t *testing.T) {
	svc, _ := newSecretBroker(t)
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	meta, err := svc.GetSecretMetadata(context.Background(), "ws-1", secret.ID)
	if err != nil {
		t.Fatalf("GetSecretMetadata: %v", err)
	}
	if meta.Ciphertext != "" {
		t.Fatalf("metadata leaked ciphertext: %q", meta.Ciphertext)
	}
	if meta.SecretType != "password" {
		t.Fatalf("type = %q", meta.SecretType)
	}
}

func TestSecretBroker_GetSecretMetadata_NotFound(t *testing.T) {
	svc, _ := newSecretBroker(t)
	_, err := svc.GetSecretMetadata(context.Background(), "ws-1", "nope")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v; want ErrSecretNotFound", err)
	}
}

func TestSecretBroker_RevealSecret_RequiresMFA(t *testing.T) {
	svc, _ := newSecretBroker(t)
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err = svc.RevealSecret(context.Background(), "ws-1", secret.ID, nil)
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("err = %v; want ErrMFARequired", err)
	}
}

func TestSecretBroker_RevealSecret_RoundTrip(t *testing.T) {
	svc, _ := newSecretBroker(t)
	plaintext := []byte("hunter2")
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  plaintext,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	got, err := svc.RevealSecret(context.Background(), "ws-1", secret.ID, []byte("mfa-token"))
	if err != nil {
		t.Fatalf("RevealSecret: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestSecretBroker_RevealSecret_NotFound(t *testing.T) {
	svc, _ := newSecretBroker(t)
	_, err := svc.RevealSecret(context.Background(), "ws-1", "nope", []byte("mfa"))
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v; want ErrSecretNotFound", err)
	}
}

func TestSecretBroker_RotateSecret_ReplacesCiphertext(t *testing.T) {
	svc, _ := newSecretBroker(t)
	old, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// VaultSecret blanks Ciphertext on the returned struct as
	// defence-in-depth, so capture the pre-rotation value by
	// reading the row back from the DB directly.
	var oldRow models.PAMSecret
	if err := svc.db.Where("id = ?", old.ID).First(&oldRow).Error; err != nil {
		t.Fatalf("read pre-rotate row: %v", err)
	}
	oldCiphertext := oldRow.Ciphertext
	if oldCiphertext == "" {
		t.Fatalf("pre-rotate ciphertext empty")
	}

	rotated, err := svc.RotateSecret(context.Background(), "ws-1", old.ID)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if rotated.LastRotatedAt == nil {
		t.Fatalf("last_rotated_at not set")
	}
	// Re-read directly from DB to confirm ciphertext column was
	// overwritten (the rotated return value blanks Ciphertext on
	// purpose).
	var row models.PAMSecret
	if err := svc.db.Where("id = ?", old.ID).First(&row).Error; err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if row.Ciphertext == "" {
		t.Fatalf("ciphertext blank after rotate")
	}
	if row.Ciphertext == oldCiphertext {
		t.Fatalf("ciphertext unchanged after rotate")
	}
}

func TestSecretBroker_RotateSecret_NotFound(t *testing.T) {
	svc, _ := newSecretBroker(t)
	_, err := svc.RotateSecret(context.Background(), "ws-1", "nope")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v; want ErrSecretNotFound", err)
	}
}

func TestSecretBroker_RotateSecret_AllSecretTypes(t *testing.T) {
	svc, _ := newSecretBroker(t)
	for _, st := range []string{"password", "ssh_key", "certificate", "token"} {
		t.Run(st, func(t *testing.T) {
			secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
				SecretType: st,
				Plaintext:  []byte("seed-" + st),
			})
			if err != nil {
				t.Fatalf("vault %s: %v", st, err)
			}
			if _, err := svc.RotateSecret(context.Background(), "ws-1", secret.ID); err != nil {
				t.Fatalf("rotate %s: %v", st, err)
			}
		})
	}
}

func TestSecretBroker_GetRotationHistory_EmptyBeforeRotate(t *testing.T) {
	svc, _ := newSecretBroker(t)
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hist, err := svc.GetRotationHistory(context.Background(), "ws-1", secret.ID)
	if err != nil {
		t.Fatalf("GetRotationHistory: %v", err)
	}
	if len(hist) != 0 {
		t.Fatalf("history = %d; want 0 before rotate", len(hist))
	}
}

func TestSecretBroker_GetRotationHistory_AfterRotate(t *testing.T) {
	svc, _ := newSecretBroker(t)
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.RotateSecret(context.Background(), "ws-1", secret.ID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	hist, err := svc.GetRotationHistory(context.Background(), "ws-1", secret.ID)
	if err != nil {
		t.Fatalf("GetRotationHistory: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history = %d; want 1", len(hist))
	}
	if hist[0].SecretID != secret.ID {
		t.Fatalf("history secret id = %q", hist[0].SecretID)
	}
}

func TestSecretBroker_CheckOutSecret_RequiresLeaseID(t *testing.T) {
	svc, _ := newSecretBroker(t)
	_, err := svc.CheckOutSecret(context.Background(), "ws-1", "sec", "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}

func TestSecretBroker_InjectSecret_AccountWithSecret(t *testing.T) {
	svc, _ := newSecretBroker(t)
	// Seed the asset + account + secret stack manually so the
	// injector has something to resolve.
	assetSvc := NewPAMAssetService(svc.db)
	asset, err := assetSvc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	sid := secret.ID
	acct, err := assetSvc.CreateAccount(context.Background(), "ws-1", asset.ID, CreateAccountInput{
		Username:    "root",
		AccountType: "shared",
		SecretID:    &sid,
		IsDefault:   true,
	})
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	got, err := svc.InjectSecret(context.Background(), "ws-1", "session-1", acct.ID)
	if err != nil {
		t.Fatalf("InjectSecret: %v", err)
	}
	if !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("injected = %q; want hunter2", got)
	}
}

func TestSecretBroker_InjectSecret_AccountWithoutSecret(t *testing.T) {
	svc, _ := newSecretBroker(t)
	assetSvc := NewPAMAssetService(svc.db)
	asset, err := assetSvc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	acct, err := assetSvc.CreateAccount(context.Background(), "ws-1", asset.ID, CreateAccountInput{
		Username:    "root",
		AccountType: "shared",
	})
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	_, err = svc.InjectSecret(context.Background(), "ws-1", "session-1", acct.ID)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}

// TestSecretBroker_InjectSecret_RejectsCrossWorkspace verifies that
// the workspace_id filter on the pam_accounts JOIN through pam_assets
// blocks a caller in workspace A from resolving an account ULID
// owned by workspace B (Devin Review finding on PR #95).
func TestSecretBroker_InjectSecret_RejectsCrossWorkspace(t *testing.T) {
	svc, _ := newSecretBroker(t)
	assetSvc := NewPAMAssetService(svc.db)
	asset, err := assetSvc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	secret, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	sid := secret.ID
	acct, err := assetSvc.CreateAccount(context.Background(), "ws-1", asset.ID, CreateAccountInput{
		Username:    "root",
		AccountType: "shared",
		SecretID:    &sid,
		IsDefault:   true,
	})
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	_, err = svc.InjectSecret(context.Background(), "ws-other", "session-1", acct.ID)
	if !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("cross-workspace inject = %v; want ErrAccountNotFound", err)
	}
}

// TestSecretBroker_InjectSecret_RejectsMissingWorkspace verifies the
// validation guard. workspace_id is mandatory so a caller cannot
// bypass the scoping by passing the empty string.
func TestSecretBroker_InjectSecret_RejectsMissingWorkspace(t *testing.T) {
	svc, _ := newSecretBroker(t)
	_, err := svc.InjectSecret(context.Background(), "", "session-1", "acct-x")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("missing workspace = %v; want ErrValidation", err)
	}
}

// TestSecretBroker_VaultSecret_BlanksCiphertextInResponse asserts
// the defence-in-depth that VaultSecret returns the struct with
// Ciphertext blanked, mirroring GetSecretMetadata + RotateSecret
// (Devin Review finding on PR #95).
func TestSecretBroker_VaultSecret_BlanksCiphertextInResponse(t *testing.T) {
	svc, _ := newSecretBroker(t)
	got, err := svc.VaultSecret(context.Background(), "ws-1", VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("VaultSecret: %v", err)
	}
	if got.Ciphertext != "" {
		t.Fatalf("Ciphertext = %q; want blanked", got.Ciphertext)
	}
}

func TestNoOpMFAVerifier_AlwaysSucceeds(t *testing.T) {
	v := NoOpMFAVerifier{}
	if err := v.VerifyStepUp(context.Background(), "user", "scope", []byte("assertion")); err != nil {
		t.Fatalf("NoOpMFAVerifier should always succeed: %v", err)
	}
}
