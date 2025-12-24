# Variables
SCRIPT_DIR := scripts
COVERAGE_OUT := coverage.out
FILTERED_COVERAGE_OUT := filtered-coverage.out
COVERAGE_HTML := coverage.html
MIN_COVERAGE := 70.0
PKG ?= ./...
TYPE ?= unit

.PHONY: help format-and-lint lint-results tests \
	coverage-check coverage-html coverage-func \
	compose-start-infra compose-start compose-stop \
	swagger-docs-gen grpc-files-gen clean

.DEFAULT_GOAL := help

help: ## Show this help message
	@echo 'Usage: make [target] [PKG=./path/to/package] [TYPE=test,types]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "; category = ""} \
		/^##@/ { category = substr($$0, 5); printf "\n\033[1m%s:\033[0m\n", category; next } \
		/^[a-zA-Z_-]+:.*?## / { printf "  \033[36m%-40s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ''
	@echo 'Test type options (TYPE parameter):'
	@echo '  unit         - Run unit tests only'
	@echo '  integration  - Run integration tests only'
	@echo '  e2e          - Run end-to-end tests only'
	@echo '  unit,integration         - Run both unit and integration tests'
	@echo '  unit,integration,e2e     - Run all test types'
	@echo ''
	@echo 'Examples:'
	@echo '  make tests                                              # Run unit tests for all packages'
	@echo '  make tests PKG=./internal/pkg/config                    # Run unit tests for specific package'
	@echo '  make tests TYPE=integration                             # Run integration tests for all packages'
	@echo '  make tests TYPE=unit,integration                        # Run unit and integration tests for all packages'
	@echo '  make tests PKG=./internal/app TYPE=integration          # Run integration tests for specific package'
	@echo '  make tests PKG=./cmd/crypto-vault-cli/e2e TYPE=e2e      # Run e2e tests for specific package'
	@echo '  make coverage-check						             # Run unit and integration tests for internal package and check code coverage'

##@  Development
format-and-lint: ## Run formatting and linting
	@echo "Running format and lint..."
	@cd $(SCRIPT_DIR) && ./format-and-lint.sh

lint-results: ## Write golang-ci lint findings to file
	@echo "Running golangci-lint..."
	@golangci-lint run | sed 's/^/- /' > linter-findings.txt
	@echo "Linting results written to linter-findings.txt"

##@  Testing
tests: ## Run tests (use PKG=./path TYPE=unit,integration,e2e)
	@echo "Running tests with types: $(TYPE) for $(PKG)..."
	@TAGS=$$(echo "$(TYPE)" | tr ',' ' '); \
	go test $(PKG) -tags="$$TAGS" -coverprofile=$(COVERAGE_OUT) -covermode=atomic
	@echo "Coverage report generated: $(COVERAGE_OUT)"
	@echo "Run 'make coverage-html' to view the HTML coverage report or 'make coverage-func' to show missing coverage"

coverage-check: ## Run unit and integration tests for internal packages and check coverage threshold
	@echo "Running unit and integration tests for internal packages..."
	@go test ./internal/... -tags="unit integration" -coverprofile=$(COVERAGE_OUT) -covermode=atomic
	@grep -v 'server.go' $(COVERAGE_OUT) > $(FILTERED_COVERAGE_OUT)
	@go tool cover -html=$(FILTERED_COVERAGE_OUT) -o $(COVERAGE_HTML)
	@echo "Coverage HTML report generated: $(COVERAGE_HTML)"
	@echo "Checking if coverage meets minimum threshold ($(MIN_COVERAGE)%)..."
	@total_coverage=$$(go tool cover -func=$(FILTERED_COVERAGE_OUT) | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ $$(echo "$$total_coverage < $(MIN_COVERAGE)" | awk '{if ($$1) exit 1; exit 0}') ]; then \
		echo "❌ Code coverage ($$total_coverage%) is below the required $(MIN_COVERAGE)% threshold"; \
		exit 1; \
	else \
		echo "✅ Code coverage check passed: $$total_coverage%"; \
	fi

##@  Coverage Reports
coverage-html: ## Generate HTML coverage report. Open HTML file using a HTML viewer in browser
	@echo "Opening coverage report in browser..."
	@go tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)

coverage-func: ## Show coverage by function in terminal
	@echo "Coverage by function:"
	@go tool cover -func=$(COVERAGE_OUT)

##@  Docker
compose-start-infra: ## Start integration test containers (postgres, azure-blob-storage)
	@echo "Spinning up integration test docker containers..."
	@docker compose up -d postgres azure-blob-storage

compose-start: ## Start all docker containers
	@echo "Spinning up docker containers..."
	@docker compose up -d --build

compose-stop: ## Stop all docker containers
	@echo "Shutting down docker containers..."
	@docker compose down -v

##@  Code Generation
swagger-docs-gen: ## Generate Swagger documentation
	@echo "Generating Swagger docs..."
	@swag init -g cmd/crypto-vault-rest-api/main.go -o cmd/crypto-vault-rest-api/docs

grpc-files-gen: ## Generate Go gRPC code from proto files
	@echo "Generating Go gRPC code from .proto files..."
	@cd $(SCRIPT_DIR) && ./grpc-files-gen.sh

##@  Cleanup
clean: ## Remove generated artifacts
	@echo "Removing artifacts..."
	@rm -rf $(COVERAGE_OUT) $(FILTERED_COVERAGE_OUT) $(COVERAGE_HTML) linter-findings.*
