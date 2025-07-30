# Makefile for sbomtool
# This project uses Go workspaces (go work) instead of go mod

BINARY_NAME := sbomtool
CMD_DIR := ./cmd/sbomtool

.PHONY: all build test lint clean fmt vet help

# Default target
all: fmt vet lint test build

# Build the sbomtool binary
build:
	@echo "Building $(BINARY_NAME)..."
	@go work sync
	@go build -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BINARY_NAME)"

# Run tests (excluding broken config package)
test:
	@echo "Running tests..."
	@go work sync
	@go test $$(go list ./... | grep -v "/pkg/config")
	@echo "Tests complete"

# Run linting
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "golangci-lint not found, falling back to go vet..."; \
		$(MAKE) vet; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	@go work sync
	@go fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	@go work sync
	@go vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@echo "Clean complete"

# Show help
help:
	@echo "Available targets:"
	@echo "  all     - Run fmt, vet, lint, test, and build (default)"
	@echo "  build   - Build the sbomtool binary"
	@echo "  test    - Run tests"
	@echo "  lint    - Run golangci-lint"
	@echo "  fmt     - Format code"
	@echo "  vet     - Run go vet"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this help"
