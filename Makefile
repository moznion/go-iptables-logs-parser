.PHONY: check ci-check test lint fmt fmt-check

check: lint fmt-check test
ci-check: fmt-check test

test:
	go test ./... -race -v -coverprofile="coverage.txt" -covermode=atomic

lint:
	golangci-lint run ./...

fmt:
	gofmt -w -s *.go **/*.go
	goimports -w *.go **/*.go

fmt-check:
	goimports -l *.go **/*.go | grep [^*][.]go$$; \
		EXIT_CODE=$$?; \
		if [ $$EXIT_CODE -eq 0 ]; then exit 1; fi

