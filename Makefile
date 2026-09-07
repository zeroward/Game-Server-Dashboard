.PHONY: fmt check test build
fmt:
	gofmt -w cmd internal web/*.go
check:
	go vet ./...
	@test -z "$$(gofmt -l cmd internal web/*.go)"
test:
	go test -race -count=1 ./...
build:
	CGO_ENABLED=0 go build -trimpath -o waypoint ./cmd/waypoint
