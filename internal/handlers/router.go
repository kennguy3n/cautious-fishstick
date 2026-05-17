package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
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

	// ConnectorHealthReader backs GET /access/connectors/:id/health
	// (Phase 7 connector health dashboard). May be nil — the route
	// is only registered when wired so dev binaries without a DB
	// stay healthy.
	ConnectorHealthReader ConnectorHealthReader

	// ConnectorListReader backs GET /access/connectors (per-workspace
	// connector catalogue with last-sync timestamps and registry-
	// derived capability flags). May be nil; the route is only
	// registered when wired.
	ConnectorListReader ConnectorListReader

	// ConnectorCatalogueReader backs GET /access/connectors/catalogue
	// (Admin UI marketplace tile grid). May be nil; the route is only
	// registered when wired so dev binaries without a DB stay healthy.
	ConnectorCatalogueReader ConnectorCatalogueReader

	// ConnectorManagementService backs POST /access/connectors, DELETE
	// /access/connectors/:id, PUT /access/connectors/:id/secret and
	// POST /access/connectors/:id/sync (per docs/architecture.md §2).
	// May be nil in dev binaries that read connectors out of a static
	// fixture; the routes are only registered when wired.
	ConnectorManagementService *access.ConnectorManagementService

	// GrantEntitlementsReader backs GET /access/grants/:id/entitlements.
	// May be nil; the entitlements sub-route is only registered when
	// wired so dev binaries without a credential manager keep serving
	// the rest of the /access/grants surface.
	GrantEntitlementsReader GrantEntitlementsReader

	// Metrics backs the /metrics Prometheus endpoint and is consulted
	// from the MetricsMiddleware to observe per-request count/latency.
	// May be nil; the middleware is then a no-op and /metrics returns
	// a minimal "up" gauge so the route stays reachable for k8s probes.
	Metrics *MetricsRegistry

	// RateLimiter governs per-workspace throttling on the /access/*
	// and /workspace/* prefixes. Set to nil to disable rate limiting
	// entirely (useful for handler tests that hammer the router in a
	// loop). When the field is omitted from a Router(Dependencies{...})
	// call site, Router constructs a default limiter from
	// ZTNA_API_RATE_LIMIT_RPS so the production wiring stays unchanged.
	RateLimiter *RateLimiter

	// DisableRateLimiter forces the rate limiter off even when
	// RateLimiter is nil. Set this in tests that need an unthrottled
	// router but don't want to manage a *RateLimiter instance.
	DisableRateLimiter bool

	// OrphanReconciler backs the Phase 11 /access/orphans surface.
	// May be nil; the routes are only registered when wired.
	OrphanReconciler OrphanReconcilerReader

	// PAMAssetService backs the /pam/assets/* endpoints (CRUD over
	// PAM inventory + per-asset account management) per
	// docs/pam/architecture.md. May be nil in dev / test binaries
	// that have not yet wired the PAM module; the routes are only
	// registered when this dependency is present.
	PAMAssetService *pam.PAMAssetService

	// SecretBrokerService backs the /pam/secrets/* endpoints
	// (vault, reveal-with-step-up-MFA, rotate). May be nil; the
	// routes are only registered when this dependency is present.
	SecretBrokerService *pam.SecretBrokerService

	// PAMMFAVerifier backs the step-up MFA gate on the secret-
	// reveal endpoint. Required when SecretBrokerService is wired;
	// dev binaries can substitute pam.NewNoOpMFAVerifier() which
	// always succeeds (with a warning log).
	PAMMFAVerifier pam.MFAVerifier

	// PAMLeaseService backs the /pam/leases/* endpoints (list +
	// revoke). May be nil; the routes are only registered when
	// this dependency is present.
	PAMLeaseService *pam.PAMLeaseService

	// PAMAuditService backs the /pam/sessions/* read surface
	// (list, detail, replay URL, command timeline, evidence
	// export, terminate) per docs/pam/architecture.md §6. May be
	// nil; the routes are only registered when this dependency
	// is present.
	PAMAuditService *pam.PAMAuditService

	// PAMPolicyAdapter backs POST /pam/policy/evaluate — the
	// gateway-facing endpoint that runs an operator-typed command
	// through PAMCommandPolicyService and returns the
	// (action, reason) pair the SSH / K8s / DB listeners enforce.
	// May be nil; the route is only registered when this
	// dependency is present so dev binaries without a DB stay
	// healthy.
	PAMPolicyAdapter *pam.SessionPolicyAdapter
}

// Router builds the *gin.Engine that serves the access platform's
// HTTP API. It registers /health and the access-platform routes
// described in docs/architecture.md (Phase 2 + Phase 3 + Phase 4 + Phase 5).
//
// Router never panics on a partial Dependencies — handlers that need
// a missing service short-circuit to 503. This is intentional: a dev
// binary started without DB credentials should still serve /health
// for k8s probes.
func Router(deps Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(RequestIDMiddleware())
	r.Use(JSONLoggerMiddleware())
	r.Use(MetricsMiddleware(deps.Metrics))
	limiter := deps.RateLimiter
	if limiter == nil && !deps.DisableRateLimiter {
		limiter = NewRateLimiter()
	}
	r.Use(limiter.Middleware())
	r.Use(JSONValidationMiddleware())

	r.GET("/health", HealthHandler)
	r.GET("/metrics", MetricsHandler(deps.Metrics))
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
		if deps.GrantEntitlementsReader != nil {
			gh.WithEntitlements(deps.GrantEntitlementsReader)
		}
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

	if deps.ConnectorHealthReader != nil {
		hh := NewConnectorHealthHandler(deps.ConnectorHealthReader)
		hh.Register(r)
	}

	if deps.ConnectorListReader != nil {
		clh := NewConnectorListHandler(deps.ConnectorListReader)
		clh.Register(r)
	}

	// Register the catalogue route BEFORE the management service so the
	// /access/connectors/catalogue path is matched against the literal
	// "catalogue" segment rather than the /access/connectors/:id route
	// that POST/DELETE handlers install. (Gin's tree handles this
	// regardless of registration order, but ordering matters when
	// reasoning about overlapping routes.)
	if deps.ConnectorCatalogueReader != nil {
		cch := NewConnectorCatalogueHandler(deps.ConnectorCatalogueReader)
		cch.Register(r)
	}

	if deps.ConnectorManagementService != nil {
		cmh := NewConnectorManagementHandler(deps.ConnectorManagementService)
		cmh.Register(r)
	}

	if deps.OrphanReconciler != nil {
		oh := NewOrphanHandler(deps.OrphanReconciler)
		oh.Register(r)
	}

	if deps.PAMAssetService != nil {
		ah := NewPAMAssetHandler(deps.PAMAssetService)
		ah.Register(r)
	}
	if deps.SecretBrokerService != nil {
		sh := NewPAMSecretHandler(deps.SecretBrokerService, deps.PAMMFAVerifier)
		sh.Register(r)
	}
	if deps.PAMLeaseService != nil {
		lh := NewPAMLeaseHandler(deps.PAMLeaseService)
		lh.Register(r)
	}
	if deps.PAMAuditService != nil {
		ah := NewPAMAuditHandler(deps.PAMAuditService)
		ah.Register(r)
	}
	if deps.PAMPolicyAdapter != nil {
		ph := NewPAMPolicyHandler(deps.PAMPolicyAdapter)
		ph.Register(r)
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
