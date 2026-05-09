// Command access-workflow-engine hosts the LangGraph workflow orchestrator
// that runs multi-step approval flows. The Phase 0 scaffold only logs
// startup; full orchestration lands in Phase 8.
package main

import (
	"log"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/google_workspace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/microsoft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
)

func main() {
	log.Printf("access-workflow-engine: starting; registered access connectors: %v", access.ListRegisteredProviders())
}
