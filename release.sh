#!/bin/bash

set -Eeo pipefail

go vet ./...

release_platform() {
    while [ $# -gt 0 ]; do
        name="./dist/go2jail-$1-$2"
        if [ "$1" = "windows" ]; then
            name="$name.exe"
        fi
        CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -o "$name" .
        shift 2
    done
}

rm -rf ./dist
mkdir -p ./dist

release_platform \
    linux amd64 \
    linux 386 \
    windows amd64 \
    darwin amd64 \
    darwin arm64 \
    linux arm64 \
    linux arm

cd ./dist
md5sum >md5.sum ./*
