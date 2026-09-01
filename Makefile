.PHONY: build test vet lint sqlc migrate-sqlite migrate-postgres clean demo demo-clean

BINARY := bin/reactor
DEMO_ROOT := /tmp/reactor-demo
DEMO_DB := sqlite://$(DEMO_ROOT)/reactor.db

build:
	go build -o $(BINARY) ./cmd/reactor

test:
	go test -race -count=1 -timeout=120s ./...

vet:
	go vet ./...

lint:
	@command -v staticcheck >/dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

sqlc:
	@command -v sqlc >/dev/null || (echo "sqlc not installed: brew install sqlc" && exit 1)
	sqlc generate

migrate-sqlite:
	go run ./cmd/reactor migrate --db sqlite://reactor.db

migrate-postgres:
	go run ./cmd/reactor migrate --db "$$REACTOR_DB_URL"

# demo bootstraps a complete local instance:
#   - state dir at /tmp/reactor-demo with a fresh master key
#   - migrated sqlite database
#   - cron-echo workflow built + registered
# After it finishes, run `bin/reactor serve --root /tmp/reactor-demo
# --db $(DEMO_DB)` and open http://127.0.0.1:7777/.
demo: build
	rm -rf $(DEMO_ROOT)
	$(BINARY) init --root $(DEMO_ROOT)
	$(BINARY) migrate --db $(DEMO_DB)
	$(BINARY) workflow build --src examples/cron-echo --slug cron-echo --root $(DEMO_ROOT)
	$(BINARY) workflow register --db $(DEMO_DB) --slug cron-echo --src examples/cron-echo/main.go --root $(DEMO_ROOT)
	$(BINARY) workflow build --src examples/welcome-customer --slug welcome-customer --root $(DEMO_ROOT)
	$(BINARY) workflow register --db $(DEMO_DB) --slug welcome-customer --src examples/welcome-customer/main.go --root $(DEMO_ROOT)
	$(BINARY) vault add --db $(DEMO_DB) --root $(DEMO_ROOT) \
		--name crm-api-key --service crm --provider shared-secret \
		--auto-rotate --interval-days 30 --value demo-crm-key-$(shell date +%s)
	$(BINARY) vault add --db $(DEMO_DB) --root $(DEMO_ROOT) \
		--name resend-api-key --service resend --provider shared-secret \
		--auto-rotate --interval-days 90 --value demo-resend-key-$(shell date +%s)
	$(BINARY) vault grant --db $(DEMO_DB) welcome-customer crm-api-key
	$(BINARY) vault grant --db $(DEMO_DB) welcome-customer resend-api-key
	@echo
	@echo "Demo ready. Two workflows registered: cron-echo, welcome-customer."
	@echo "Two credentials seeded: crm-api-key (30d auto-rotate), resend-api-key (90d auto-rotate)."
	@echo "Start the daemon with:"
	@echo "  $(BINARY) serve --root $(DEMO_ROOT) --db $(DEMO_DB)"
	@echo "Then open http://127.0.0.1:7777/ and http://127.0.0.1:7777/credentials"

demo-clean:
	rm -rf $(DEMO_ROOT)

clean:
	rm -rf bin/ reactor.db reactor.db-journal $(DEMO_ROOT)
