// Command pam-gateway is the protocol-proxy binary that brokers
// privileged sessions between operators and target assets (SSH, K8s,
// DB) per docs/pam/architecture.md §4.
//
// Phase 1 wires only the SSH listener; the K8s and DB protocols
// will land in follow-up milestones behind the same config + audit
// surfaces. The binary is intentionally narrow: every privileged
// decision (authorise this session, fetch this credential, append
// this command to the recording) is delegated to the ztna-api REST
// surface so the gateway never holds long-lived keys or maps to
// the data plane directly.
//
// Boot flow:
//  1. Load config from environment (PAM_GATEWAY_*).
//  2. Initialise the SSH session authorizer (ztna-api client).
//  3. Initialise the SSH CA (if PAM_GATEWAY_SSH_CA_KEY is set);
//     otherwise the gateway falls back to credential injection.
//  4. Start the SSH listener on PAM_GATEWAY_SSH_PORT.
//  5. Start the health HTTP server on PAM_GATEWAY_HEALTH_PORT.
//  6. Block on SIGINT/SIGTERM; on signal cancel the listener
//     contexts and drain in-flight sessions up to
//     pam_gatewayShutdownTimeout.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/gateway"
)

// pamGatewayShutdownTimeout bounds the graceful drain on SIGTERM
// so a wedged session cannot keep the process alive indefinitely.
const pamGatewayShutdownTimeout = 30 * time.Second

func main() {
	// `--healthcheck` is a self-probe mode used by the docker-compose
	// healthcheck command (the distroless runtime image has no curl).
	// It performs a quick HTTP GET against the local /health endpoint
	// and exits 0/1 based on the response.
	for _, arg := range os.Args[1:] {
		if arg == "--healthcheck" || arg == "-healthcheck" {
			os.Exit(runHealthcheck())
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("pam-gateway: load config: %v", err)
	}
	log.Printf("pam-gateway: starting ssh_port=%d health_port=%d api_url=%s", cfg.SSHPort, cfg.HealthPort, redactURL(cfg.APIURL))

	// Pass nil (not http.DefaultClient) so the constructors install
	// a client with a 5-second per-request timeout. http.DefaultClient
	// is non-nil but has Timeout=0, which bypasses the safety-net
	// fallback and lets an unresponsive ztna-api hang InjectSecret
	// indefinitely (Devin Review finding on PR #95).
	authz := gateway.NewAPIAuthorizer(cfg.APIURL, cfg.APIKey, nil)
	injector := gateway.NewAPISecretInjector(cfg.APIURL, cfg.APIKey, nil)
	commandSink := gateway.NewAPICommandSink(cfg.APIURL, cfg.APIKey, nil)
	policyEval := gateway.NewAPIPolicyEvaluator(cfg.APIURL, cfg.APIKey, nil)

	var replayStore gateway.ReplayStore
	if cfg.ReplayDir != "" {
		fs, err := gateway.NewFilesystemReplayStore(cfg.ReplayDir)
		if err != nil {
			log.Fatalf("pam-gateway: init replay store: %v", err)
		}
		replayStore = fs
		log.Printf("pam-gateway: replay store rooted at %s", fs.Root())
	} else {
		log.Printf("pam-gateway: PAM_GATEWAY_REPLAY_DIR unset — session recordings disabled")
	}

	var ca *gateway.SSHCertificateAuthority
	if cfg.SSHCAKeyPath != "" {
		ca, err = gateway.LoadSSHCAFromPath(cfg.SSHCAKeyPath, cfg.SSHCAValidity)
		if err != nil {
			log.Fatalf("pam-gateway: load ssh ca: %v", err)
		}
		log.Printf("pam-gateway: ssh ca loaded fingerprint=%s validity=%s", ca.Fingerprint(), cfg.SSHCAValidity)
	} else {
		log.Printf("pam-gateway: ssh ca unset — falling back to credential injection only")
	}

	hostKey, err := gateway.LoadOrGenerateHostKey(cfg.SSHHostKeyPath)
	if err != nil {
		log.Fatalf("pam-gateway: load host key: %v", err)
	}

	listener, err := gateway.NewSSHListener(gateway.SSHListenerConfig{
		Port:          cfg.SSHPort,
		HostKey:       hostKey,
		Authorizer:    authz,
		Injector:      injector,
		CA:            ca,
		ReplayStore:   replayStore,
		CommandSink:   commandSink,
		CommandPolicy: policyEval,
	})
	if err != nil {
		log.Fatalf("pam-gateway: build ssh listener: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := listener.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("pam-gateway: ssh listener exited: %v", err)
		}
	}()

	healthSrv := &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(cfg.HealthPort)),
		Handler:           healthHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("pam-gateway: health server listening on :%d", cfg.HealthPort)
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("pam-gateway: health server exited: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("pam-gateway: shutdown signal received, draining for up to %s", pamGatewayShutdownTimeout)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), pamGatewayShutdownTimeout)
	defer shutdownCancel()
	if err := healthSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("pam-gateway: health server shutdown: %v", err)
	}
	wg.Wait()
	log.Printf("pam-gateway: stopped")
}

// healthHandler returns the /health endpoint handler. The endpoint
// is intentionally cheap — it returns 200 unconditionally so
// orchestrators can pick the readiness signal up without consulting
// the upstream ztna-api.
func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}

// redactURL strips any embedded user-info from the URL string so
// the boot log does not leak basic-auth credentials. Best-effort —
// production configurations should use header-based auth (which
// this binary already prefers).
//
// The fallthrough case (URL contains "@" but no "://") still
// redacts the user-info segment by replacing the prefix with
// "***" — falling through to "return u" would leak credentials
// on a malformed URL (Devin Review finding on PR #95).
func redactURL(u string) string {
	if u == "" {
		return ""
	}
	// Quick-and-dirty redaction; full url.Parse is overkill here.
	at := -1
	for i := 0; i < len(u); i++ {
		if u[i] == '@' {
			at = i
		}
	}
	if at < 0 {
		return u
	}
	for i := 0; i < len(u); i++ {
		if u[i] == ':' && i+1 < len(u) && u[i+1] == '/' && i+2 < len(u) && u[i+2] == '/' {
			return u[:i+3] + "***" + u[at:]
		}
	}
	// No "://" scheme prefix found but the URL still has an "@",
	// so the segment before it is almost certainly user-info.
	// Strip it unconditionally rather than leaking it.
	return "***" + u[at:]
}

// config carries the resolved PAM_GATEWAY_* environment values.
type config struct {
	SSHPort        int
	HealthPort     int
	APIURL         string
	APIKey         string
	S3Bucket       string
	S3Region       string
	ReplayDir      string
	SSHHostKeyPath string
	SSHCAKeyPath   string
	SSHCAValidity  time.Duration
}

// loadConfig resolves the binary's runtime configuration from
// environment variables. Required vars surface as a single
// fmt.Errorf so misconfiguration fails loudly at boot.
func loadConfig() (config, error) {
	cfg := config{
		SSHPort:        2222,
		HealthPort:     8081,
		APIURL:         os.Getenv("PAM_GATEWAY_API_URL"),
		APIKey:         os.Getenv("PAM_GATEWAY_API_KEY"),
		S3Bucket:       os.Getenv("PAM_S3_BUCKET"),
		S3Region:       os.Getenv("PAM_S3_REGION"),
		ReplayDir:      os.Getenv("PAM_GATEWAY_REPLAY_DIR"),
		SSHHostKeyPath: os.Getenv("PAM_GATEWAY_SSH_HOST_KEY"),
		SSHCAKeyPath:   os.Getenv("PAM_GATEWAY_SSH_CA_KEY"),
		SSHCAValidity:  5 * time.Minute,
	}
	if v := os.Getenv("PAM_GATEWAY_SSH_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("PAM_GATEWAY_SSH_PORT=%q: %w", v, err)
		}
		cfg.SSHPort = n
	}
	if v := os.Getenv("PAM_GATEWAY_HEALTH_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("PAM_GATEWAY_HEALTH_PORT=%q: %w", v, err)
		}
		cfg.HealthPort = n
	}
	if v := os.Getenv("PAM_GATEWAY_SSH_CA_VALIDITY"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("PAM_GATEWAY_SSH_CA_VALIDITY=%q: %w", v, err)
		}
		cfg.SSHCAValidity = d
	}
	if cfg.APIURL == "" {
		return cfg, errors.New("PAM_GATEWAY_API_URL is required")
	}
	// API key is optional for the dev compose stack (matches the
	// ztna-api side, which also accepts an empty key locally). In
	// production deployments the helm chart sets the env var to a
	// rotating secret.
	return cfg, nil
}

// runHealthcheck issues a short-timeout GET against the local
// /health endpoint and reports the exit code the docker-compose
// healthcheck should observe. The listen port is read from the same
// env var the main server uses so port overrides work transparently.
func runHealthcheck() int {
	port := os.Getenv("PAM_GATEWAY_HEALTH_PORT")
	if port == "" {
		port = "8081"
	}
	// Allow operators to pass either a bare port (8081) or a full
	// ":8081" suffix without rejecting one of the forms.
	port = strings.TrimPrefix(port, ":")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
