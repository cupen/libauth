.PHONY: test build run examples vet bench clean

vet:
	go vet ./...

test: vet
	go test ./... -race

# Benchmarks behind the numbers in README.md.
bench:
	go test -bench=. -benchmem -benchtime=3s -run=^$$ ./authz ./jwt ./branca

build:
	go build -o bin/example ./_examples/example01

examples:
	go build -o bin/examples-basic ./_examples/basic
	go build -o bin/examples-customstore ./_examples/customstore
	go build -o bin/examples-jwtauth ./_examples/jwtauth

run:
	go run ./_examples/example01

clean:
	rm -rf bin
