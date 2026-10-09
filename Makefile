.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo)
LDFLAGS := -s -w \
	-X github.com/bredda/tavian/internal/version.Version=$(VERSION) \
	-X github.com/bredda/tavian/internal/version.Commit=$(COMMIT)

COMPOSE := docker compose -f deploy/compose/docker-compose.yml

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the binaries into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tavian ./cmd/tavian
	CGO_ENABLED=0 go build -trimpath -o bin/mockllm ./cmd/mockllm

.PHONY: test
test: ## Run tests with the race detector
	go test -race -count=1 ./...

.PHONY: test-db
test-db: ## Run the tests including PostgreSQL integration (starts a throwaway container)
	-docker rm -f tavian-test-pg >/dev/null 2>&1
	docker run -d --rm --name tavian-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=tavian -p 127.0.0.1:55432:5432 postgres:17-alpine >/dev/null
	@until docker exec tavian-test-pg pg_isready -U postgres -d tavian >/dev/null 2>&1; do sleep 0.5; done
	TAVIAN_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/tavian sh -c 'go test -race -count=1 ./... && go test -tags e2e -race -count=1 ./e2e' ; status=$$?; docker rm -f tavian-test-pg >/dev/null; exit $$status

.PHONY: policy-test
policy-test: ## Run the example policy fixtures through the gateway's decision code
	go run ./cmd/tavian policy test -config configs/policy-tests/tavian.yaml configs/policy-tests/cases

.PHONY: fuzz
fuzz: ## Fuzz the request extractor and the inspection engine (FUZZTIME=30s each)
	go test -run '^$$' -fuzz FuzzExtractChat -fuzztime $(or $(FUZZTIME),30s) ./internal/provider/openai
	go test -run '^$$' -fuzz FuzzEngine -fuzztime $(or $(FUZZTIME),30s) ./internal/inspect

.PHONY: bench
bench: ## Benchmark content inspection
	go test -run '^$$' -bench . -benchmem ./internal/inspect

.PHONY: conformance
conformance: ## Run the OpenAI SDK conformance suite (needs Python 3 and Node)
	conformance/run.sh

.PHONY: demo-e2e
demo-e2e: ## Play the demo scenario of docs/VISION.md against the docker compose stack (needs Docker)
	scripts/demo-e2e.sh

.PHONY: cover
cover: ## Run tests and print total coverage
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

.PHONY: lint
lint: ## Run golangci-lint (must be installed)
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format the code
	gofmt -w .

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	go mod tidy

.PHONY: run
run: ## Run the gateway with ./tavian.yaml (copy configs/tavian.example.yaml first)
	go run ./cmd/tavian serve -config tavian.yaml

.PHONY: keygen
keygen: ## Generate an API key and its config hash
	go run ./cmd/tavian keygen

.PHONY: demo
demo: ## Start the demo stack (gateway, PostgreSQL, Keycloak, mock backend) on localhost:8080
	$(COMPOSE) up --build -d
	@echo "Try: curl -s localhost:8080/v1/models -H 'Authorization: Bearer tav_VavQsTNlrxWVesBv7GinuMLhYBbmhns_YNloIcWS3UI'"

.PHONY: demo-token
demo-token: ## Print an access token from the demo Keycloak (DEMO_USER=alice|bob)
	@curl -sf localhost:8081/realms/tavian/protocol/openid-connect/token \
		-d grant_type=password -d client_id=tavian-demo -d username=$(or $(DEMO_USER),alice) -d password=$(or $(DEMO_USER),alice) \
		| sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'

.PHONY: demo-down
demo-down: ## Stop the demo stack
	$(COMPOSE) down

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist coverage.out
