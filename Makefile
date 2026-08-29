.PHONY: test build run examples vet clean

vet:
	go vet ./...

test: vet
	go test ./... -race

build:
	go build -o bin/example ./cmd/example

examples:
	go build -o bin/examples-basic ./examples/basic
	go build -o bin/examples-customstore ./examples/customstore

run:
	go run ./cmd/example

clean:
	rm -rf bin
