.PHONY: build test acceptance acceptance-half acceptance-full node control frontend docker nodes node-a node-b node-c

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

build:
	mkdir -p bin
	cd node && go build -o ../bin/jolt-node ./backend/cmd/jolt-node
	cd control/frontend && npm run build
	cd control && CGO_ENABLED=1 go build -o ../bin/jolt-control ./cmd/jolt-control

test:
	cd node && go test ./...
	cd control && CGO_ENABLED=1 go test ./...

acceptance:
	cd node && JOLT_ACCEPTANCE_PROFILE=quick go test -tags=acceptance -run '^TestAcceptance' -timeout 15m ./backend/internal/services/jobs

acceptance-half:
	cd node && JOLT_ACCEPTANCE_PROFILE=half go test -tags=acceptance -run '^TestAcceptance' -timeout 2h ./backend/internal/services/jobs

acceptance-full:
	cd node && JOLT_ACCEPTANCE_PROFILE=full go test -tags=acceptance -run '^TestAcceptance' -timeout 4h ./backend/internal/services/jobs

node:
	cd node && CONTROL_TOWER_TOKEN=development-token go run ./backend/cmd/jolt-node

nodes:
	@echo "Starting nodeA on http://127.0.0.1:$(NODE_A_API_PORT)"
	@echo "Starting nodeB on http://127.0.0.1:$(NODE_B_API_PORT)"
	@echo "Starting nodeC on http://127.0.0.1:$(NODE_C_API_PORT)"
	@echo "Use Ctrl+C to stop all nodes."
	@$(MAKE) --no-print-directory -j3 node-a node-b node-c

node-a:
	@mkdir -p "$(TESTDATA_ROOT)/nodeA/data" "$(TESTDATA_ROOT)/nodeA/keys" "$(TESTDATA_ROOT)/nodeA/files"
	@cd node && \
		NODE_NAME=nodeA \
		API_ADDRESS=127.0.0.1:$(NODE_A_API_PORT) \
		MTLS_ADDRESS=127.0.0.1:$(NODE_A_MTLS_PORT) \
		MTLS_PUBLIC_ENDPOINT=https://127.0.0.1:$(NODE_A_MTLS_PORT) \
		CONTROL_TOWER_TOKEN="$(NODE_A_TOKEN)" \
		JOLT_DATA_DIR="$(TESTDATA_ROOT)/nodeA/data" \
		JOLT_KEYS_DIR="$(TESTDATA_ROOT)/nodeA/keys" \
		go run ./backend/cmd/jolt-node

node-b:
	@mkdir -p "$(TESTDATA_ROOT)/nodeB/data" "$(TESTDATA_ROOT)/nodeB/keys" "$(TESTDATA_ROOT)/nodeB/files"
	@cd node && \
		NODE_NAME=nodeB \
		API_ADDRESS=127.0.0.1:$(NODE_B_API_PORT) \
		MTLS_ADDRESS=127.0.0.1:$(NODE_B_MTLS_PORT) \
		MTLS_PUBLIC_ENDPOINT=https://127.0.0.1:$(NODE_B_MTLS_PORT) \
		CONTROL_TOWER_TOKEN="$(NODE_B_TOKEN)" \
		JOLT_DATA_DIR="$(TESTDATA_ROOT)/nodeB/data" \
		JOLT_KEYS_DIR="$(TESTDATA_ROOT)/nodeB/keys" \
		go run ./backend/cmd/jolt-node

node-c:
	@mkdir -p "$(TESTDATA_ROOT)/nodeC/data" "$(TESTDATA_ROOT)/nodeC/keys" "$(TESTDATA_ROOT)/nodeC/files"
	@cd node && \
		NODE_NAME=nodeC \
		API_ADDRESS=127.0.0.1:$(NODE_C_API_PORT) \
		MTLS_ADDRESS=127.0.0.1:$(NODE_C_MTLS_PORT) \
		MTLS_PUBLIC_ENDPOINT=https://127.0.0.1:$(NODE_C_MTLS_PORT) \
		CONTROL_TOWER_TOKEN="$(NODE_C_TOKEN)" \
		JOLT_DATA_DIR="$(TESTDATA_ROOT)/nodeC/data" \
		JOLT_KEYS_DIR="$(TESTDATA_ROOT)/nodeC/keys" \
		go run ./backend/cmd/jolt-node

control:
	cd control/frontend && npm run build
	cd control && CGO_ENABLED=1 CONTROL_TOWER_ADMIN_PASSWORD=development-password CONTROL_TOWER_DB_ENCRYPTION_KEY=development-encryption-key-32chars go run ./cmd/jolt-control

frontend:
	cd control/frontend && npm run dev

docker:
	docker compose build
