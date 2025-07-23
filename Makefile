# HTTPSeal Makefile

.PHONY: build clean test install lint fmt vet deps help

# Variables
BINARY_NAME=httpseal
BUILD_DIR=build
CMD_DIR=cmd/httpseal
GO_FILES=$(shell find . -type f -name '*.go')

# Default target
all: build

# Build the binary
build: deps
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(BINARY_NAME)
	@rm -rf ca/

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	@go vet ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@if which golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping lint"; \
	fi

# Install the binary with capabilities
install: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Setting capabilities..."
	@sudo setcap 'cap_net_bind_service,cap_sys_admin=+ep' /usr/local/bin/$(BINARY_NAME)
	@echo "$(BINARY_NAME) installed to /usr/local/bin/ with required capabilities"

# Development build (with debug info)
dev: deps
	@echo "Building development version..."
	@mkdir -p $(BUILD_DIR)
	@go build -race -gcflags="all=-N -l" -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Run with example command
run-example: build
	@echo "Running example: httpseal wget https://httpbin.org/get"
	@./$(BUILD_DIR)/$(BINARY_NAME) wget https://httpbin.org/get

# Check if required capabilities are set
check-caps:
	@echo "Checking capabilities..."
	@if [ -f "/usr/local/bin/$(BINARY_NAME)" ]; then \
		getcap /usr/local/bin/$(BINARY_NAME); \
	else \
		echo "$(BINARY_NAME) not installed in /usr/local/bin/"; \
	fi

# Show help
help:
	@echo "HTTPSeal Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build the binary"
	@echo "  clean       Clean build artifacts"
	@echo "  test        Run tests"
	@echo "  fmt         Format code"
	@echo "  vet         Vet code"
	@echo "  lint        Lint code (requires golangci-lint)"
	@echo "  deps        Install dependencies"
	@echo "  install     Install binary with capabilities"
	@echo "  dev         Build development version"
	@echo "  run-example Run example command"
	@echo "  check-caps  Check installed capabilities"
	@echo "  help        Show this help message"