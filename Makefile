# Xfuzz — build and quality targets.
#
# The target names match docs/TESTS.md section 13. Each maps to a numbered test
# layer from that document; the layer is named in the target's comment so the
# strategy and the tooling cannot drift apart.

MODULE      := github.com/rom/Xfuzz
BIN         := bin
CMDS        := xfuzz xfuzzd xfuzz-worker xfuzz-cc xfuzz-sandbox

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
LDFLAGS     := -X $(MODULE)/internal/version.Version=$(VERSION) \
	              -X $(MODULE)/internal/version.Commit=$(COMMIT) \
	              -X $(MODULE)/internal/version.Date=$(DATE)

GO          ?= go
BENCHTIME   ?= 1s
BENCHCOUNT  ?= 5
FUZZTIME    ?= 30s
THRESHOLD   ?= 0.10

# Cross-compilation targets checked in CI (ASR-0006).
PLATFORMS   := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all
all: lint test build

# ---------------------------------------------------------------- build ------

.PHONY: build
build: ## Build every command into bin/
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		echo "  build $$c"; \
		$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

.PHONY: cross
cross: ## Verify every supported platform compiles with CGO disabled (ASR-0006)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "  cross $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -o /dev/null ./... || exit 1; \
	done

.PHONY: install-tools
install-tools: ## Install the external tools CI uses
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

# ----------------------------------------------------------------- test ------

.PHONY: test
test: ## Layers 1-2: unit, property, and round-trip tests
	$(GO) test -race ./...

.PHONY: test-integration
test-integration: ## Layers 3, 4, 5, 8: planted bugs, determinism, differential, fault injection
	$(GO) test -race -tags integration -timeout 30m ./...

.PHONY: test-security
test-security: ## Layer 12: sandbox escape, scope guard, audit integrity
	$(GO) test -race -tags security -timeout 15m ./...

.PHONY: test-all
test-all: lint test test-integration test-security bench-check ## Everything except extended fuzzing

.PHONY: cover
cover: ## Unit tests with a coverage profile
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -1

# ----------------------------------------------------------------- fuzz ------

.PHONY: fuzz
fuzz: ## Layer 7: run every fuzz target against its seed corpus
	$(GO) test -run '^Fuzz' ./...

.PHONY: fuzz-target
fuzz-target: ## Layer 7: fuzz one target continuously — make fuzz-target PKG=./pkg/codec FUZZ=FuzzDecode
	@test -n "$(PKG)" -a -n "$(FUZZ)" || { echo "usage: make fuzz-target PKG=./pkg/codec FUZZ=FuzzDecode"; exit 2; }
	$(GO) test $(PKG) -run '^$$' -fuzz '^$(FUZZ)$$' -fuzztime $(FUZZTIME)

# ------------------------------------------------------------ benchmarks -----

.PHONY: bench
bench: ## Layer 6: run benchmarks, writing bench/current.txt
	@mkdir -p bench
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) -count $(BENCHCOUNT) ./... \
		| tee bench/current.txt

.PHONY: bench-baseline
bench-baseline: ## Record the current measurements as the gated baseline
	@mkdir -p bench
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) -count $(BENCHCOUNT) ./... \
		| tee bench/baseline.txt
	@echo "baseline recorded in bench/baseline.txt — commit it with the change that justifies it"

.PHONY: bench-check
bench-check: bench ## Layer 6: fail on a regression beyond THRESHOLD
	$(GO) run ./tools/benchcmp -baseline bench/baseline.txt -current bench/current.txt -threshold $(THRESHOLD)

# ----------------------------------------------------------------- lint ------

.PHONY: lint
lint: fmt-check vet lint-arch lint-docs lint-license ## All static checks

.PHONY: fmt
fmt: ## Rewrite sources with gofmt
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if anything is not gofmt-clean
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: lint-arch
lint-arch: ## Enforce the layering rules of docs/ARCHITECTURE.md section 2
	$(GO) test ./tools/archlint/

.PHONY: lint-docs
lint-docs: ## Layer 10: ASR/ADR traceability and link resolution
	$(GO) test ./tools/docslint/

.PHONY: lint-license
lint-license: ## Layer 10: dependency licence policy of ADR-0018
	$(GO) test ./tools/licensecheck/

.PHONY: vuln
vuln: ## Known-vulnerability scan
	govulncheck ./...

# ------------------------------------------------------------------- ci ------

.PHONY: ci
ci: lint test cross bench-check ## What CI runs on every push

.PHONY: clean
clean:
	rm -rf $(BIN) coverage.out bench/current.txt

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
