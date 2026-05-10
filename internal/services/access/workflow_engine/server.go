package workflow_engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// Server is the HTTP front-end of the workflow engine. It exposes:
//
//	GET  /health           — liveness probe
//	POST /workflows/execute — run a workflow definition for a request
//
// Server is intentionally bare-metal net/http; the engine doesn't have
// a routing dependency yet and a 2-route service doesn't need one.
type Server struct {
	executor *WorkflowExecutor
	mux      *http.ServeMux
	// startedAt is captured at construction so /health can report
	// uptime without a global clock.
	startedAt time.Time
	// healthy is flipped to 0 by Shutdown so /health 503s during
	// drain. Atomic int32 to avoid sync.Mutex on the hot path.
	healthy atomic.Int32
}

// NewServer wires a Server around the provided executor. Use
// Server.Handler with http.ListenAndServe (or http.Server.ListenAndServe).
func NewServer(executor *WorkflowExecutor) *Server {
	s := &Server{
		executor:  executor,
		mux:       http.NewServeMux(),
		startedAt: time.Now(),
	}
	s.healthy.Store(1)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/workflows/execute", s.handleExecute)
	return s
}

// Handler returns the http.Handler for the server.
func (s *Server) Handler() http.Handler { return s.mux }

// Shutdown flips the health bit so /health responds 503; intended for
// graceful drain. The caller is responsible for stopping the
// http.Server.
func (s *Server) Shutdown() { s.healthy.Store(0) }

// healthResponse is the JSON shape served by /health.
type healthResponse struct {
	Status     string `json:"status"`
	UptimeSec  int64  `json:"uptime_seconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.healthy.Load() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, healthResponse{
			Status:    "draining",
			UptimeSec: int64(time.Since(s.startedAt).Seconds()),
		})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:    "ok",
		UptimeSec: int64(time.Since(s.startedAt).Seconds()),
	})
}

// errorResponse is the JSON shape returned for any non-2xx response.
type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	defer r.Body.Close()

	var req ExecuteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("decode body: %v", err)})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result, err := s.executor.Execute(ctx, &req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrInvalidRequest):
			status = http.StatusBadRequest
		case errors.Is(err, ErrWorkflowNotFound):
			status = http.StatusNotFound
		case errors.Is(err, ErrStepUnknown):
			status = http.StatusUnprocessableEntity
		}
		log.Printf("workflow_engine: execute %s: %v", req.WorkflowID, err)
		writeJSON(w, status, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
