package main

import (
	"strings"
	"testing"
)

// TestRedactDSN_URLForm pins the original URL-style redaction
// path. Three concerns matter here:
//
//  1. The user:password segment is replaced with [redacted] so a
//     log line copy-pasted into a ticket doesn't leak the secret.
//  2. LastIndex("@") is used so passwords containing '@' (which
//     libpq accepts unescaped) don't truncate the redaction
//     window and accidentally bleed the password into the host.
//  3. The non-redacted "scheme://" and "@host/db?..." segments
//     are preserved verbatim so operators can still see which
//     host/db the binary connected to.
func TestRedactDSN_URLForm(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "simple url",
			in:   "postgres://access:access@postgres:5432/access?sslmode=disable",
			want: "postgres://[redacted]@postgres:5432/access?sslmode=disable",
		},
		{
			name: "password contains @",
			in:   "postgres://access:p@ss@postgres:5432/access",
			want: "postgres://[redacted]@postgres:5432/access",
		},
		{
			name: "no credentials in url",
			in:   "postgres://postgres:5432/access",
			want: "postgres://postgres:5432/access",
		},
		{
			name: "non-postgres scheme passthrough",
			in:   "sqlite:///tmp/db",
			want: "sqlite:///tmp/db",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := redactDSN(tc.in)
			if got != tc.want {
				t.Errorf("redactDSN(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedactDSN_KeyValueForm pins the libpq key=value path. libpq
// accepts both URL and key=value DSNs (see
// https://www.postgresql.org/docs/current/libpq-connect.html); the
// access platform documents URL, but a misconfigured deployment
// could pass key=value and silently leak the password through the
// startup log. Each case asserts the password value never appears
// in the redacted output AND that surrounding key=value tokens
// (host, dbname, etc.) survive intact so operators can still
// debug.
func TestRedactDSN_KeyValueForm(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// secret must NOT appear anywhere in the redacted output.
		secret string
		// preserve is a list of tokens that must survive
		// redaction. Use this to assert that the redactor
		// doesn't over-eagerly delete the non-password
		// segments.
		preserve []string
	}{
		{
			name:     "bare password",
			in:       "host=localhost user=access password=hunter2 dbname=access sslmode=disable",
			secret:   "hunter2",
			preserve: []string{"host=localhost", "user=access", "dbname=access", "sslmode=disable", "password=[redacted]"},
		},
		{
			name:     "single-quoted password with spaces",
			in:       "host=localhost user=access password='se cret 123' dbname=access",
			secret:   "se cret 123",
			preserve: []string{"host=localhost", "user=access", "dbname=access", "password=[redacted]"},
		},
		{
			name:     "uppercase PASSWORD key",
			in:       "host=localhost PASSWORD=hunter2 dbname=access",
			secret:   "hunter2",
			preserve: []string{"host=localhost", "dbname=access"},
		},
		{
			name:     "whitespace around equals",
			in:       "host=localhost password = hunter2 dbname=access",
			secret:   "hunter2",
			preserve: []string{"host=localhost", "dbname=access"},
		},
		{
			name:     "no password key",
			in:       "host=localhost dbname=access sslmode=disable",
			secret:   "",
			preserve: []string{"host=localhost", "dbname=access", "sslmode=disable"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := redactDSN(tc.in)
			if tc.secret != "" && strings.Contains(got, tc.secret) {
				t.Errorf("redactDSN(%q) = %q; leaks secret %q", tc.in, got, tc.secret)
			}
			for _, tok := range tc.preserve {
				if !strings.Contains(got, tok) {
					t.Errorf("redactDSN(%q) = %q; missing expected token %q", tc.in, got, tok)
				}
			}
		})
	}
}

// TestRedactDSN_KeyValueHostWithAt covers the cross-cutting case
// where the key=value DSN contains an '@' in one of the values
// (e.g. host=foo@example.com via a DNS alias). The URL branch's
// LastIndex("@") logic would otherwise misinterpret this as a
// URL-style credential boundary; the implementation gates the URL
// branch behind a "://" check so this case stays on the key=value
// path and the password is still scrubbed.
func TestRedactDSN_KeyValueHostWithAt(t *testing.T) {
	in := "host=foo@example.com password=hunter2 dbname=access"
	got := redactDSN(in)
	if strings.Contains(got, "hunter2") {
		t.Errorf("redactDSN(%q) = %q; leaks password despite '@' in host value", in, got)
	}
	if !strings.Contains(got, "host=foo@example.com") {
		t.Errorf("redactDSN(%q) = %q; truncated host=foo@example.com instead of leaving it intact", in, got)
	}
}
