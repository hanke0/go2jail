#!/bin/bash

export CGO_ENABLED=0

go vet ./... || exit 1
content=$(go fmt ./...)
if [ -n "$content" ]; then
    echo "$content"
    echo >&2 "files not well formatted"
    exit 1
fi
go test --timeout 60s --cover --coverpkg=./... ./... || exit 1
