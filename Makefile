build:
	go build -ldflags="-X main.version=$(shell git describe --tags --always --dirty)" -o $(shell basename $(PWD)) .

install:
	go install -ldflags="-X main.version=$(shell git describe --tags --always --dirty)" .