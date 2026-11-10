# Makefile for building and smoke-testing tarpit-fuzz on its own.
# See tools/tarpit-fuzz/README.md for the full tour.

BIN      ?= ../../bin/tarpit-fuzz
GO       ?= go
PACKAGE  := github.com/rom/Xfuzz/tools/tarpit-fuzz

.PHONY: all build test list smoke clean

all: build

build:
	$(GO) build -o $(BIN) $(PACKAGE)/cmd

test:
	$(GO) test -count=1 $(PACKAGE)/engine

list: build
	$(BIN) --list | head -20
	@echo "..."
	$(BIN) --list | tail -5

# A smoke run against a honeypot the caller has already started on 127.0.0.1.
smoke: build
	$(BIN) -c configs/protocols.yaml --iterations 32 --rounds 1 --target 127.0.0.1

clean:
	rm -f $(BIN)
