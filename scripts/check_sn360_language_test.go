// scripts/check_sn360_language_test.go drives scripts/check_sn360_language.sh
// from `go test` so CI failures surface with the same toolchain that
// runs the rest of the test suite. The test is skipped when bash is
// unavailable so Windows developers can still run `go test ./...`.
//
// The test creates a temporary handler file containing a deliberate
// SN360 language violation and asserts the script exits non-zero with
// a diagnostic referencing the forbidden phrase. It then creates a
// clean file and asserts a zero exit.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func scriptPath(t *testing.T) string {
	t.Helper()
	_, current, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(current), "check_sn360_language.sh")
}

func TestCheckSN360Language_FlagsViolations(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(bad, []byte(`package x
var _ = "ZTNA policy violations"
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := exec.Command("bash", scriptPath(t), dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", out)
	}
	if !strings.Contains(string(out), "ZTNA policy") {
		t.Errorf("output did not mention forbidden phrase: %s", out)
	}
}

func TestCheckSN360Language_PassesOnCleanInput(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	dir := t.TempDir()
	clean := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(clean, []byte(`package x
var _ = "Access rule created"
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := exec.Command("bash", scriptPath(t), dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected zero exit; output: %s; err: %v", out, err)
	}
}
