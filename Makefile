IMAGE ?= credentials-bot-manager:latest

.PHONY: tidy build docker-build test clean

tidy:
	docker run --rm -v "$$(pwd):/app" -w /app golang:1.24-alpine go mod tidy

build:
	docker run --rm -v "$$(pwd):/app" -w /app golang:1.24-alpine \
		go build -ldflags="-s -w" -o bin/credentials-bot-manager main.go

docker-build:
	docker build -t $(IMAGE) .

test:
	docker run --rm -v "$$(pwd):/app" -w /app golang:1.24-alpine go test -v ./...

clean:
	rm -rf bin/
