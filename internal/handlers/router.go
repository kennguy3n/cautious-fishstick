package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// Dependencies bundles the service-layer hooks the handlers need.
// Construct one from cmd/ztna-api/main.go after wiring the DB,
// AccessProvisioningService, and aiclient. Every field is optional
// at the type level — handlers gracefully return 503 when a
// dependency they need is missing rather than panicking. This keeps
// the surface forgiving for tests and partially-configured dev
// binaries (e.g. AI off in local development).
type Dependencies struct {
	// PolicyService backs the /workspace/policy/* endpoints.
	PolicyService *access.PolicyService

	// AccessRequestService backs the /access/requests/* endpoints.
	AccessRequestService *access.AccessRequestService

	// AccessReviewService backs the /access/reviews/* endpoints.
	AccessReviewService *access.AccessReviewService

	// AccessGrantReader backs GET /access/grants. The interface is
	// satisfied by *access.AccessGrantQueryService (see
	// internal/services/access/access_grant_query_service.go); a
	// custom implementation can be wired in for tests or for
	// alternative storage layers.
	AccessGrantReader AccessGrantReader

	// AIService backs POST /access/explain and /access/suggest. May
	// be nil in dev / test where the AI agent is intentionally not
	// configured; the handlers return 503 with a structured error.
	AIService AIInvoker

	// JMLService backs the /scim/Users endpoints (Phase 6 inbound
	// SCIM). When nil the SCIM endpoints are not registered — a
	// dev binary without a JML service stays healthy without
	// surfacing dummy 503s on every SCIM probe.
	JMLService *access.JMLService

	// SCIMResolver backs the /scim/Users endpoints alongside
	// JMLService. Required if JMLService is non-nil. The resolver
	// translates inbound SCIM payloads into the JML service's
	// JoinerInput / MoverInput / leaver tuples.
	SCIMResolver SCIMUserResolver
}

// Router builds the *gin.Engine that serves the access platform's
// HTTP API. It registers /health and the access-platform routes
// described in docs/PHASES.md (Phase 2 + Phase 3 + Phase 4 + Phase 5).
//
// Router never panics on a partial Dependencies — handlers that need
// a missing service short-circuit to 503. This is intentional: a dev
// binary started without DB credentials should still serve /health
// for k8s probes.
func Router(deps Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", HealthHandler)
	r.GET("/swagger", SwaggerHandler)
	r.GET("/swagger.json", SwaggerHandler)
	r.GET("/swagger.yaml", SwaggerYAMLHandler)

	if deps.PolicyService != nil {
		ph := NewPolicyHandler(deps.PolicyService)
		ph.Register(r)
	}
	if deps.AccessRequestService != nil {
		arh := NewAccessRequestHandler(deps.AccessRequestService)
		arh.Register(r)
	}
	if deps.AccessGrantReader != nil {
		gh := NewAccessGrantHandler(deps.AccessGrantReader)
		gh.Register(r)
	}
	if deps.AccessReviewService != nil {
		rh := NewAccessReviewHandler(deps.AccessReviewService)
		rh.Register(r)
	}

	// AI handlers (explain / suggest) are registered even when the
	// AI service is nil so callers see a structured 503 from the
	// handler itself rather than a 404.
	aih := NewAIHandler(deps.AIService)
	aih.Register(r)

	if deps.JMLService != nil && deps.SCIMResolver != nil {
		sh := NewSCIMHandler(deps.JMLService, deps.SCIMResolver)
		sh.Register(r)
	}

	return r
}

// HealthHandler responds 200 OK to GET /health with a tiny JSON
// envelope. Used by Kubernetes liveness / readiness probes and by
// the smoke tests that come up during deployment.
//
// Health is intentionally lightweight: it does NOT touch the DB or
// the AI agent. A failing DB should be visible through metrics, not
// through the readiness probe — otherwise a momentary DB hiccup
// removes every pod from rotation simultaneously and amplifies the
// outage.
func HealthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}
