// Package docker_test owns the regression guard that locks in the
// "every long-running compose service must declare a healthcheck"
// invariant. The CI workflow (`.github/workflows/ci.yml`) already
// relies on `docker compose up --wait`, which exits non-zero unless
// every named service either has no `--wait` selector or reports
// healthy — but a future refactor that drops a healthcheck would
// silently regress the `--wait` semantics. This test fails fast
// instead, with a precise file:line for the missing entry.
package docker_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// composePath is the project-relative path to the dev stack. The
// test walks up to the repo root since `go test ./...` runs from
// the package directory.
const composePath = "../../docker-compose.yml"

// servicesExemptFromHealthcheck enumerates services that
// intentionally ship without a healthcheck. Today the only such
// service is `access-connector-worker`, a queue consumer that
// exits with code 0 after draining its queue — including it under
// `docker compose up --wait` would race `--wait` against worker
// shutdown (see the matching comment in
// `.github/workflows/ci.yml`).
var servicesExemptFromHealthcheck = map[string]string{
	"access-connector-worker": "queue consumer that exits 0 after draining; no `--wait` target",
}

// serviceHeader matches a top-level service stanza in
// docker-compose.yml. The compose spec indents service names by
// exactly two spaces under the top-level `services:` key, so the
// regex anchors on that to avoid catching nested keys such as
// `environment:` or `healthcheck:` that happen to start with two
// spaces.
var serviceHeader = regexp.MustCompile(`^  ([a-zA-Z0-9_-]+):\s*$`)

// TestDockerCompose_EveryServiceHasHealthcheck asserts every
// service block under `services:` in docker-compose.yml declares a
// `healthcheck:` key (or appears in servicesExemptFromHealthcheck).
// Missing healthchecks regress `docker compose up --wait` from a
// real gate into a race against startup ordering, which has bitten
// us in prior CI breakages — hence the explicit guard.
func TestDockerCompose_EveryServiceHasHealthcheck(t *testing.T) {
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	lines := strings.Split(string(raw), "\n")

	// Find the `services:` block boundary so we don't accidentally
	// scan top-level `volumes:` or `networks:` entries (which also
	// indent their children by two spaces).
	servicesStart, servicesEnd := -1, len(lines)
	for i, ln := range lines {
		trim := strings.TrimRight(ln, " \t\r")
		if trim == "services:" {
			servicesStart = i + 1
			continue
		}
		if servicesStart >= 0 && i > servicesStart {
			// A new top-level key (zero indent, non-empty,
			// non-comment) ends the services block.
			if len(trim) > 0 && !strings.HasPrefix(trim, " ") && !strings.HasPrefix(trim, "#") && !strings.HasPrefix(trim, "\t") {
				servicesEnd = i
				break
			}
		}
	}
	if servicesStart < 0 {
		t.Fatalf("could not find top-level `services:` key in %s", composePath)
	}

	// Walk the services block, collecting one entry per service
	// header along with whether a `healthcheck:` line appears
	// before the next sibling service header.
	type entry struct {
		name string
		line int
		hc   bool
	}
	var services []entry
	cur := -1
	for i := servicesStart; i < servicesEnd; i++ {
		if m := serviceHeader.FindStringSubmatch(lines[i]); m != nil {
			services = append(services, entry{name: m[1], line: i + 1})
			cur = len(services) - 1
			continue
		}
		if cur < 0 {
			continue
		}
		// healthcheck: blocks live at four-space indent under the
		// service header. Match that strictly so a string literal
		// like `# healthcheck: legacy` in a comment elsewhere
		// can't false-positive.
		if strings.HasPrefix(lines[i], "    healthcheck:") {
			services[cur].hc = true
		}
	}

	if len(services) == 0 {
		t.Fatalf("no services parsed from %s — parser may be broken", composePath)
	}

	for _, s := range services {
		if s.hc {
			continue
		}
		if reason, ok := servicesExemptFromHealthcheck[s.name]; ok {
			t.Logf("%s:%d: service %q skipped (%s)", composePath, s.line, s.name, reason)
			continue
		}
		t.Errorf("%s:%d: service %q has no healthcheck (add `healthcheck:` block or list it in servicesExemptFromHealthcheck with a reason)", composePath, s.line, s.name)
	}
}

// TestDockerCompose_ExemptionsAreStillUsed fails when a service
// listed in servicesExemptFromHealthcheck no longer exists in
// docker-compose.yml. This stops the exemption list from rotting
// silently — a removed service that returns later would otherwise
// inherit the old exemption and quietly opt out of the
// healthcheck gate.
func TestDockerCompose_ExemptionsAreStillUsed(t *testing.T) {
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	body := string(raw)
	for name, reason := range servicesExemptFromHealthcheck {
		// Match either the YAML service header form ("  name:")
		// or the dependency-list form ("- name") so a service
		// referenced only as a dependency doesn't trip the check.
		if !strings.Contains(body, "  "+name+":") {
			t.Errorf("service %q is in servicesExemptFromHealthcheck (%s) but is no longer declared in %s — drop the exemption or rename the service in the map", name, reason, composePath)
		}
	}
}
