// scripts/check_no_model_files_test.go drives scripts/check_no_model_files.sh
// from `go test` so CI failures surface with the same toolchain that
// runs the rest of the test suite. The test is skipped when bash is
// unavailable so Windows developers can still run `go test ./...`.
//
// The test creates a temporary sdk-shaped directory containing a
// deliberate on-device model file and asserts the script exits non-zero
// with a diagnostic referencing the forbidden extension. It then creates
// a clean directory and asserts a zero exit. A third case scans the
// repository's own sdk/ tree to guarantee main stays clean.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func modelScriptPath(t *testing.T) string {
	t.Helper()
	_, current, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(current), "check_no_model_files.sh")
}

func TestCheckNoModelFiles_FlagsViolations(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "ios", "Resources", "model.mlmodel")
	if err := os.MkdirAll(filepath.Dir(bad), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(bad, []byte("synthetic mlmodel for test"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := exec.Command("bash", modelScriptPath(t), dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", out)
	}
	if !strings.Contains(string(out), "mlmodel") {
		t.Errorf("output did not mention forbidden extension: %s", out)
	}
}

func TestCheckNoModelFiles_FlagsEachForbiddenExtension(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	for _, ext := range []string{"mlmodel", "tflite", "onnx", "gguf"} {
		ext := ext
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			bad := filepath.Join(dir, "weights."+ext)
			if err := os.WriteFile(bad, []byte("synthetic test weights"), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			cmd := exec.Command("bash", modelScriptPath(t), dir)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf(".%s extension was not flagged; output: %s", ext, out)
			}
			if !strings.Contains(string(out), "."+ext) {
				t.Errorf("output did not mention .%s: %s", ext, out)
			}
		})
	}
}

func TestCheckNoModelFiles_PassesOnCleanInput(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	dir := t.TempDir()
	clean := filepath.Join(dir, "ios", "Sources", "Client.swift")
	if err := os.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(clean, []byte("import Foundation\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := exec.Command("bash", modelScriptPath(t), dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected zero exit; output: %s; err: %v", out, err)
	}
}

func TestCheckNoModelFiles_PassesOnRepoSDK(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	cmd := exec.Command("bash", modelScriptPath(t))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("repository sdk/ tree is dirty; output: %s; err: %v", out, err)
	}
}
