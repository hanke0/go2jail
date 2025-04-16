#!/bin/bash

set -Eeo pipefail

release_platform() {
    while [ $# -gt 0 ]; do
        name="./dist/go2jail-$1-$2"
        if [ "$1" = "windows" ]; then
            name="$name.exe"
        fi
        CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build \
            -ldflags "$ldflags" \
            -o "$name" .
        shift 2
    done
}

rm -rf ./dist
mkdir -p ./dist

goversion=$(go version | sed 's/go version //g')
time=$(date +%Y-%m-%dT%H:%M:%S%z)
dirty=
if ! git diff-files --quiet; then
    dirty="-dirty"
fi
revid="$(git rev-parse HEAD)${dirty}"
tag=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
if [ -z "$tag" ]; then
    latesttag=$(git show-ref --tags -d | tail -1 | grep -Eo 'v[a-z0-9\.\-]+')
    if [ -z "$latesttag" ]; then
        latesttag="v0.0.1-unknown"
    fi
    tag="${latesttag}-dev${dirty}"
else
    tag="${tag}${dirty}"
fi

ldflags="-X 'main.Version=$tag' -X 'main.GoVersion=$goversion' -X 'main.Rev=$revid' -X 'main.BuildTime=$time' "

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
