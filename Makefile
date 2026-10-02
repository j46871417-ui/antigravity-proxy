.PHONY: build run clean test

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o antigravity-proxy .

run:
	go run .

test:
	go test -v ./...

clean:
	rm -f antigravity-proxy
