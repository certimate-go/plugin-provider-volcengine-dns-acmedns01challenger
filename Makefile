.PHONY: build test

build:
	GOWORK=off go build -mod=readonly -o volcengine-dns.exe .

test:
	GOWORK=off go test -mod=readonly ./...
