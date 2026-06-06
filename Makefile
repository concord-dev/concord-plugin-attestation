BIN := bin/concord-plugin-attestation
VERSION ?= v0.1.0
INSTALL_DIR := $(HOME)/.concord/plugins/attestation/$(VERSION)

.PHONY: build install test clean

build:
	go build -o $(BIN) .

test:
	go test ./... -count=1

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BIN) $(INSTALL_DIR)/concord-plugin-attestation

clean:
	rm -rf bin
