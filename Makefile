.PHONY: build test vet vulncheck check acceptance acceptance-half acceptance-full node control frontend docker nodes node-a node-b node-c

TESTDATA_ROOT := $(abspath node/testdata)

NODE_A_API_PORT ?= 18081
NODE_B_API_PORT ?= 18082
NODE_C_API_PORT ?= 18083

NODE_A_MTLS_PORT ?= 18441
NODE_B_MTLS_PORT ?= 18442
NODE_C_MTLS_PORT ?= 18443

NODE_A_TOKEN ?= development-node-a-token
NODE_B_TOKEN ?= development-node-b-token
NODE_C_TOKEN ?= development-node-c-token

NODE_DEV_ENCRYPTION_KEY ?= AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=

build:
	mkdir -p bin
	cd node && CGO_ENABLED=0 go build -o ../bin/jolt-node ./backend/cmd/jolt-node
	cd control/frontend && npm run build
	cd control && CGO_ENABLED=1 go build -o ../bin/jolt-control ./cmd/jolt-control

test:
	cd node && CGO_ENABLED=0 go test ./...
	cd control && CGO_ENABLED=1 go test ./...
	cd control/frontend && npm test

vet:
	cd node && CGO_ENABLED=0 go vet ./...
	cd control && CGO_ENABLED=1 go vet ./...
	cd control/frontend && npm run typecheck

vulncheck:
	cd node && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd control && go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Mirrors the CI gate.
check: build vet test acceptance

acceptance:
	cd node && CGO_ENABLED=0 JOLT_ACCEPTANCE_PROFILE=quick go test -tags=acceptance -run '^TestAcceptance' -v -timeout 15m ./backend/internal/services/jobs ./backend/internal/infra/state

acceptance-half:
	cd node && CGO_ENABLED=0 JOLT_ACCEPTANCE_PROFILE=half go test -tags=acceptance -run '^TestAcceptance' -timeout 2h ./backend/internal/services/jobs

acceptance-full:
	cd node && CGO_ENABLED=0 JOLT_ACCEPTANCE_PROFILE=full go test -tags=acceptance -run '^TestAcceptance' -timeout 4h ./backend/internal/services/jobs

node:
	@cd node && CGO_ENABLED=0 CONTROL_TOWER_TOKEN=development-token JOLT_STATE_ENCRYPTION_KEY="$(NODE_DEV_ENCRYPTION_KEY)" go run ./backend/cmd/jolt-node

nodes:
	@echo "Starting nodeA on http://127.0.0.1:$(NODE_A_API_PORT)"
	@echo "Starting nodeB on http://127.0.0.1:$(NODE_B_API_PORT)"
	@echo "Starting nodeC on http://127.0.0.1:$(NODE_C_API_PORT)"
	@echo "Use Ctrl+C to stop all nodes."
	@$(MAKE) --no-print-directory -j3 node-a node-b node-c

node-a:
	@CONTROL_TOWER_TOKEN="$(NODE_A_TOKEN)" JOLT_STATE_ENCRYPTION_KEY="$(NODE_DEV_ENCRYPTION_KEY)" python3 scripts/dev-node.py nodeA --api $(NODE_A_API_PORT) --mtls $(NODE_A_MTLS_PORT)

node-b:
	@CONTROL_TOWER_TOKEN="$(NODE_B_TOKEN)" JOLT_STATE_ENCRYPTION_KEY="$(NODE_DEV_ENCRYPTION_KEY)" python3 scripts/dev-node.py nodeB --api $(NODE_B_API_PORT) --mtls $(NODE_B_MTLS_PORT)

node-c:
	@CONTROL_TOWER_TOKEN="$(NODE_C_TOKEN)" JOLT_STATE_ENCRYPTION_KEY="$(NODE_DEV_ENCRYPTION_KEY)" python3 scripts/dev-node.py nodeC --api $(NODE_C_API_PORT) --mtls $(NODE_C_MTLS_PORT)


control:
	cd control/frontend && npm run build
	cd control && CGO_ENABLED=1 CONTROL_TOWER_ADMIN_PASSWORD=development-password CONTROL_TOWER_DB_ENCRYPTION_KEY=development-encryption-key-32chars go run ./cmd/jolt-control

frontend:
	cd control/frontend && npm run dev

docker:
	docker compose build
