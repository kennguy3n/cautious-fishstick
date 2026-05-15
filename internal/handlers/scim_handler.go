package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// SCIMUserResolver is the narrow service contract the SCIM handler
// needs to translate an inbound SCIM payload into the JML service's
// JoinerInput / MoverInput shape. Implementations resolve user
// attributes and group memberships into the (TeamIDs, DefaultGrants)
// tuple the JML orchestrator runs against connectors.
//
// The handler does not own the resolution policy — that lives in
// the policy engine + connector registry. The interface is tiny so
// tests can stub it without a real DB.
type SCIMUserResolver interface {
	// ResolveJoiner maps a SCIM POST /Users payload to the JoinerInput
	// the JML service consumes. workspaceID is the multi-tenant scope
	// the handler resolves from the request before dispatch.
	ResolveJoiner(ctx context.Context, workspaceID string, payload SCIMUserPayload) (access.JoinerInput, error)

	// ResolveMover maps a SCIM PATCH /Users/:id payload onto the
	// MoverInput the JML service consumes. The resolver is responsible
	// for diffing the old vs new attribute / group set; the handler
	// only carries the SCIM payload across.
	ResolveMover(ctx context.Context, workspaceID, externalID string, payload SCIMUserPayload) (access.MoverInput, error)

	// ResolveLeaver maps a SCIM DELETE /Users/:id (or PATCH with
	// Active=false) onto the (workspaceID, internalUserID) tuple
	// HandleLeaver consumes. Returns ErrSCIMUserNotFound when the
	// externalID does not match a known user.
	ResolveLeaver(ctx context.Context, workspaceID, externalID string) (userID string, err error)
}

// SCIMUserPayload is the minimal SCIM v2.0 user shape the handler
// understands. We deliberately accept a permissive subset rather
// than full SCIM v2.0 so the handler does not couple to upstream
// schema quirks; the resolver is free to enrich.
type SCIMUserPayload struct {
	Schemas    []string                 `json:"schemas,omitempty"`
	ExternalID string                   `json:"externalId,omitempty"`
	UserName   string                   `json:"userName,omitempty"`
	Active     *bool                    `json:"active,omitempty"`
	Name       *SCIMNamePayload         `json:"name,omitempty"`
	Emails     []SCIMEmailPayload       `json:"emails,omitempty"`
	Groups     []SCIMGroupPayload       `json:"groups,omitempty"`
	Operations []SCIMPatchOperation     `json:"Operations,omitempty"`
	Extra      map[string]interface{}   `json:"-"`
}

// SCIMNamePayload mirrors the SCIM Name complex type subset the
// handler exposes. The full SCIM Name type has more fields (middle
// name, honorific prefix, ...) which we accept and ignore.
type SCIMNamePayload struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

// SCIMEmailPayload mirrors the SCIM Email multi-valued attribute.
type SCIMEmailPayload struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroupPayload mirrors the SCIM Group multi-valued attribute.
// Value is the group's external ID.
type SCIMGroupPayload struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// SCIMPatchOperation mirrors the SCIM PATCH operation envelope per
// RFC 7644 §3.5.2. The handler classifies group / attribute changes
// off the Op + Path tuple; the resolver consumes the full list.
type SCIMPatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// SCIMHandler bundles the inbound SCIM v2.0 endpoints — POST,
// PATCH, DELETE on /scim/Users — and routes them through the JML
// service's joiner / mover / leaver lanes.
//
// Per docs/overview.md §5.4 SCIM is the canonical inbound channel
// for JML automation. The handler is intentionally thin: it parses
// the payload, classifies the event, asks the resolver for the
// JML input, and dispatches to the JML service. All policy /
// attribute resolution lives in the resolver.
type SCIMHandler struct {
	jmlService *access.JMLService
	resolver   SCIMUserResolver
	// workspaceFor resolves the workspace for an inbound SCIM
	// request. SCIM does not natively carry a workspace_id, so
	// production deployments wire this from the auth middleware
	// (e.g. derive from the API key / OIDC subject). The default
	// is a no-op that returns an empty string so unconfigured dev
	// binaries surface a 400 rather than silently routing into the
	// wrong tenant.
	workspaceFor func(c *gin.Context) string
}

// NewSCIMHandler returns a handler bound to the supplied JML service
// and resolver. Both must be non-nil — a SCIM endpoint without a
// resolver is misconfigured.
func NewSCIMHandler(jml *access.JMLService, resolver SCIMUserResolver) *SCIMHandler {
	return &SCIMHandler{
		jmlService: jml,
		resolver:   resolver,
		workspaceFor: func(c *gin.Context) string {
			// Tests + dev binaries pass workspace_id as a query
			// parameter; production uses an auth-middleware-set
			// gin context value. The shape here is forgiving so
			// the handler stays testable without auth.
			ws := GetPtrStringQuery(c, "workspace_id")
			if ws != nil {
				return *ws
			}
			return ""
		},
	}
}

// SetWorkspaceResolver replaces the workspace-resolution hook. Used
// by cmd/ztna-api/main.go to wire an auth-middleware-aware resolver.
func (h *SCIMHandler) SetWorkspaceResolver(fn func(c *gin.Context) string) {
	if fn != nil {
		h.workspaceFor = fn
	}
}

// Register wires the handler's routes onto r. SCIM verbs follow
// RFC 7644: POST /scim/Users (create), PATCH /scim/Users/:id
// (update), DELETE /scim/Users/:id (deactivate).
func (h *SCIMHandler) Register(r *gin.Engine) {
	g := r.Group("/scim/Users")
	g.POST("", h.CreateUser)
	g.PATCH("/:id", h.PatchUser)
	g.DELETE("/:id", h.DeleteUser)
}

// CreateUser handles POST /scim/Users. The payload is classified as
// a joiner (or leaver, when Active=false) and dispatched to the JML
// service.
func (h *SCIMHandler) CreateUser(c *gin.Context) {
	var payload SCIMUserPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	workspaceID := h.workspaceFor(c)
	if workspaceID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id is required for SCIM operations",
			Code:    "validation_failed",
			Message: "workspace_id is required for SCIM operations",
		})
		return
	}

	kind := h.jmlService.ClassifyChange(access.SCIMEvent{
		Operation: http.MethodPost,
		Active:    payload.Active,
	})

	switch kind {
	case access.JMLEventJoiner:
		in, err := h.resolver.ResolveJoiner(c.Request.Context(), workspaceID, payload)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err)
			return
		}
		res, err := h.jmlService.HandleJoiner(c.Request.Context(), in)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err)
			return
		}
		c.JSON(scimResponseStatus(res), res)
	case access.JMLEventLeaver:
		userID, err := h.resolver.ResolveLeaver(c.Request.Context(), workspaceID, payload.ExternalID)
		if err != nil {
			h.handleResolverErr(c, err)
			return
		}
		res, err := h.jmlService.HandleLeaver(c.Request.Context(), workspaceID, userID)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err)
			return
		}
		c.JSON(scimResponseStatus(res), res)
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "unable to classify SCIM POST event",
			Code:    "validation_failed",
			Message: "unable to classify SCIM POST event",
		})
	}
}

// PatchUser handles PATCH /scim/Users/:id. Active=false routes to
// the leaver lane; group / attribute changes route to the mover
// lane; an empty PATCH (no group / attribute changes) is rejected
// with 400 so callers don't silently no-op.
func (h *SCIMHandler) PatchUser(c *gin.Context) {
	externalID := GetStringParam(c, "id")
	if externalID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "user id is required",
			Code:    "validation_failed",
			Message: "user id is required",
		})
		return
	}
	var payload SCIMUserPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	workspaceID := h.workspaceFor(c)
	if workspaceID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id is required for SCIM operations",
			Code:    "validation_failed",
			Message: "workspace_id is required for SCIM operations",
		})
		return
	}

	hasGroupChanges, hasAttrChanges, deactivated := classifyPatchOps(payload)
	// Major SCIM providers (Azure AD, Okta) signal user deactivation
	// inside the Operations array (path="active" with value false, or
	// a path-less op whose value sub-object contains active=false)
	// rather than as a top-level "active" JSON field. When the body
	// has no top-level Active but classifyPatchOps detected such a
	// deactivation op, synthesise Active=false here so ClassifyChange
	// routes the request through the leaver lane (revoke all grants,
	// purge all team memberships) instead of the mover lane (selective
	// team-diff). Routing a deactivation through the mover lane would
	// leave the user with active grants after the IdP considers them
	// deactivated — exactly the JML lifecycle invariant we cannot
	// violate.
	active := payload.Active
	if deactivated && active == nil {
		falseVal := false
		active = &falseVal
	}
	kind := h.jmlService.ClassifyChange(access.SCIMEvent{
		Operation:           http.MethodPatch,
		Active:              active,
		HasGroupChanges:     hasGroupChanges,
		HasAttributeChanges: hasAttrChanges,
	})

	switch kind {
	case access.JMLEventLeaver:
		userID, err := h.resolver.ResolveLeaver(c.Request.Context(), workspaceID, externalID)
		if err != nil {
			h.handleResolverErr(c, err)
			return
		}
		res, err := h.jmlService.HandleLeaver(c.Request.Context(), workspaceID, userID)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err)
			return
		}
		c.JSON(scimResponseStatus(res), res)
	case access.JMLEventMover:
		in, err := h.resolver.ResolveMover(c.Request.Context(), workspaceID, externalID, payload)
		if err != nil {
			h.handleResolverErr(c, err)
			return
		}
		res, err := h.jmlService.HandleMover(c.Request.Context(), in)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err)
			return
		}
		c.JSON(scimResponseStatus(res), res)
	default:
		// JMLEventUnknown — the PATCH carries no fields that drive
		// JML automation. SCIM providers SHOULD avoid sending
		// such PATCHes; surfacing a 400 makes the misuse visible
		// rather than silently no-op'ing.
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "PATCH carries no JML-relevant changes",
			Code:    "validation_failed",
			Message: "PATCH must include group or attribute changes",
		})
	}
}

// DeleteUser handles DELETE /scim/Users/:id. SCIM treats DELETE as
// "permanent deactivation" — every active grant is revoked and
// every team membership is dropped.
func (h *SCIMHandler) DeleteUser(c *gin.Context) {
	externalID := GetStringParam(c, "id")
	if externalID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "user id is required",
			Code:    "validation_failed",
			Message: "user id is required",
		})
		return
	}
	workspaceID := h.workspaceFor(c)
	if workspaceID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id is required for SCIM operations",
			Code:    "validation_failed",
			Message: "workspace_id is required for SCIM operations",
		})
		return
	}
	userID, err := h.resolver.ResolveLeaver(c.Request.Context(), workspaceID, externalID)
	if err != nil {
		h.handleResolverErr(c, err)
		return
	}
	res, err := h.jmlService.HandleLeaver(c.Request.Context(), workspaceID, userID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(scimResponseStatus(res), res)
}

// handleResolverErr translates resolver-layer errors into HTTP
// statuses. The known sentinel is ErrSCIMUserNotFound — surfaced as
// 404 — anything else is a 5xx.
func (h *SCIMHandler) handleResolverErr(c *gin.Context, err error) {
	if errors.Is(err, ErrSCIMUserNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, errorEnvelope{
			Error:   err.Error(),
			Code:    "not_found",
			Message: err.Error(),
		})
		return
	}
	writeError(c, http.StatusInternalServerError, err)
}

// scimResponseStatus picks the HTTP status for a JMLResult. A clean
// run is 200; a partial-failure run is 207 (Multi-Status) so SCIM
// providers can surface the per-grant detail to the operator.
func scimResponseStatus(r *access.JMLResult) int {
	if r != nil && r.AllOK() {
		return http.StatusOK
	}
	return http.StatusMultiStatus
}

// classifyPatchOps walks the SCIM PATCH operations list and reports
// whether any operation touches group membership, user attributes
// (display name, email, ...), or signals user deactivation
// (active=false). Used to drive ClassifyChange in PatchUser.
//
// Two SCIM provider conventions for deactivation are handled:
//
//   - Azure AD style: explicit path="active" with a stringified
//     boolean value (e.g. {"op":"Replace","path":"active",
//     "value":"False"}).
//   - Okta style: path-less op whose value is a sub-object
//     containing active=false (e.g. {"op":"replace",
//     "value":{"active": false}}).
//
// In both cases payload.Active stays nil because there is no
// top-level "active" JSON field; only inspecting Operations
// reveals the deactivation signal.
func classifyPatchOps(p SCIMUserPayload) (groups, attrs, deactivation bool) {
	for _, op := range p.Operations {
		path := op.Path
		switch {
		case strings.EqualFold(path, "groups"), strings.EqualFold(path, "members"):
			groups = true
		case strings.EqualFold(path, "active"):
			// active flips are attribute changes (so a re-enable
			// flows through the mover lane), but explicit
			// active=false additionally signals deactivation.
			attrs = true
			if isFalseValue(op.Value) {
				deactivation = true
			}
		case path == "":
			// SCIM allows path-less PATCH where the payload value
			// is a sub-object. Conservatively treat as both
			// group + attribute changes, then look inside the
			// sub-object for an explicit active=false toggle.
			groups = true
			attrs = true
			if m, ok := op.Value.(map[string]interface{}); ok {
				for k, v := range m {
					if strings.EqualFold(k, "active") && isFalseValue(v) {
						deactivation = true
					}
				}
			}
		default:
			attrs = true
		}
	}
	// Direct attribute / group changes on the payload itself (e.g.
	// SCIM PUT-style PATCH replacing the whole user) are also
	// classified.
	if len(p.Groups) > 0 {
		groups = true
	}
	if p.Name != nil || len(p.Emails) > 0 || p.UserName != "" {
		attrs = true
	}
	return groups, attrs, deactivation
}

// isFalseValue reports whether v decodes to a logical false. SCIM
// providers vary in how they encode the active=false signal: Azure
// AD historically sends it as the JSON string "False" (note the
// casing) while strict providers send the JSON boolean false. Both
// must classify as deactivation.
func isFalseValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return !x
	case string:
		return strings.EqualFold(x, "false")
	}
	return false
}

// ErrSCIMUserNotFound is the sentinel resolvers return when an
// inbound SCIM externalID does not match a known user. The handler
// translates this into HTTP 404 per RFC 7644 §3.6.
var ErrSCIMUserNotFound = errors.New("scim: user not found")
