# cautious-fishstick — developer entrypoint
#
# Targets mirror the .github/workflows/ci.yml steps so a clean
# checkout can run the same gates locally with one command per
# stage. Run `make help` for a categorised summary.
#
# Conventions:
#   - Go tests always pass `-race -timeout=180s` to match CI.
#   - Docker targets use `docker compose` (v2), not legacy
#     `docker-compose`.
#   - Python targets live under cmd/access-ai-agent/ which has its
#     own requirements.txt and pytest suite.

.DEFAULT_GOAL := help

# --- Go ---------------------------------------------------------------

.PHONY: build
build: ## go build ./...
	go build ./...

.PHONY: vet
vet: ## go vet ./...
	go vet ./...

.PHONY: test
test: ## go test -race -timeout=180s ./...
	go test -race -timeout=180s ./...

.PHONY: test-short
test-short: ## go test -race -timeout=60s -short ./...
	go test -race -timeout=60s -short ./...

.PHONY: test-integration
test-integration: ## go test -race -timeout=300s -tags=integration ./... (build-tagged integration suite)
	go test -race -timeout=300s -tags=integration ./...

# --- Python ----------------------------------------------------------

.PHONY: test-python
test-python: ## pytest cmd/access-ai-agent/tests/
	cd cmd/access-ai-agent && python -m pytest tests/ -v

# --- Code quality / CI gates ----------------------------------------

.PHONY: swagger
swagger: ## regenerate docs/swagger.{json,yaml}
	bash scripts/generate-swagger.sh

.PHONY: swagger-check
swagger-check: ## fail if swagger spec is stale (CI gate)
	bash scripts/generate-swagger.sh --check

.PHONY: sn360-check
sn360-check: ## fail if SN360 user-facing vocabulary regressed (CI gate)
	bash scripts/check_sn360_language.sh

.PHONY: model-check
model-check: ## fail if an on-device model file landed under sdk/ (CI gate)
	bash scripts/check_no_model_files.sh

.PHONY: stale-ref-check
stale-ref-check: ## fail if a retired doc filename is referenced outside docs/internal/ (CI gate)
	bash scripts/check_stale_references.sh

# --- Docker ----------------------------------------------------------

.PHONY: docker-up
docker-up: ## docker compose up --build --wait
	docker compose up --build --wait

.PHONY: docker-down
docker-down: ## docker compose down -v
	docker compose down -v --remove-orphans

.PHONY: docker-logs
docker-logs: ## docker compose logs --no-color --tail=200
	docker compose logs --no-color --tail=200

# --- Aggregates -----------------------------------------------------

.PHONY: lint
lint: vet swagger-check sn360-check model-check stale-ref-check ## run every CI lint gate

.PHONY: ci
ci: vet test swagger-check sn360-check model-check stale-ref-check ## run every CI gate locally

# --- Help -----------------------------------------------------------

.PHONY: help
help: ## print this help
	@printf "Common targets:\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
