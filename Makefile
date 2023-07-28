golangcilint_version := "1.53.3"

default : lint test

.PHONY: lint
lint:
	@echo "Linting..."
	@(which golangci-lint &&  [[ "$$(golangci-lint --version | awk '{print $$4}')" == "$(golangcilint_version)" ]] ) || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v$(golangcilint_version)
	@golangci-lint run

.PHONY: test
test:
	go test -race ./...
