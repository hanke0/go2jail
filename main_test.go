package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
)

func makeTestConfig(t *testing.T, content string) string {
	t.Helper()
	tpl, err := template.New(t.Name()).Parse(content)
	require.NoError(t, err)
	dir, err := os.MkdirTemp("", "go2jail-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	var s strings.Builder
	err = tpl.Execute(&s, map[string]string{
		"dir": dir,
	})
	require.NoError(t, err)
	text := s.String()
	err = os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(text), 0777)
	require.NoError(t, err)
	return dir
}

func writeTestNft(t *testing.T, dir string) string {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, "nft"), []byte(`#!/bin/bash

dir=$(dirname "$0")
echo "dir: $dir"
echo "$@" >>"$dir/nft.log"
`), 0777)
	require.NoError(t, err)
	path := os.Getenv("PATH")
	newpath := dir + ":" + path
	err = os.Setenv("PATH", newpath)
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Setenv("PATH", path)
	})
	return filepath.Join(dir, "nft.log")
}

func TestBasicLogAndNftReject(t *testing.T) {
	dir := makeTestConfig(t, `
jail:
  - id: nft
    type: nftset
    sudo: false # run nft command without sudo
    nft_executable: nft # nft executable path
    rule: inet # nft rule name
    table: filter # nft table name
    ipv4_set: ipv4_block_set # nft set name for ipv4
    ipv6_set: ipv6_block_set # nft set name for ipv6
discipline:
  - id: test
    source: log
    jail: [nft]
    files: [{{.dir}}/test.log]
    regexes: ['%(ip)']
    limit: 1/1s
`)
	watchfile := filepath.Join(dir, "test.log")
	err := os.WriteFile(watchfile, nil, 0777)
	require.NoError(t, err)
	nftlog := writeTestNft(t, dir)

	flags := Flags{
		ConfigDir: dir,
		LogLevel:  "debug",
	}
	wait, stop, err := entry(&flags)
	require.NoError(t, err)

	s, err := Execute(ExecuteOptions{
		Program:    []string{"bash", "-c", "echo -e '1.1.1.1\n2.2.2.2' >" + watchfile},
		OutputSize: 1024,
	})
	require.NoError(t, err, s)
	for range 50 {
		_, err := os.Stat(nftlog)
		if err == nil {
			break
		}
		if os.IsNotExist(err) {
			time.Sleep(time.Millisecond * 100)
			continue
		}
		stop()
		wait()
		t.Fatal(err)
	}
	stop()
	wait()

	b, err := os.ReadFile(nftlog)
	require.NoError(t, err)
	require.Equal(t, `add element inet filter ipv4_block_set { 1.1.1.1 }
add element inet filter ipv4_block_set { 2.2.2.2 }
`, string(b))
}

func TestTestingWorks(t *testing.T) {
	dir := makeTestConfig(t, `
jail:
  - id: log
    type: log
discipline:
  - id: test
    source: log
    jail: [log]
    files: [{{.dir}}/test.log]
    regexes: ['%(ip)']
    limit: 1/s
`)
	watchfile := filepath.Join(dir, "test.log")
	err := os.WriteFile(watchfile, []byte("1.1.1.1\n2.2.2.2\n"), 0777)
	require.NoError(t, err)

	stdout := Stdout
	t.Cleanup(func() {
		Stdout = stdout
	})
	var bs strings.Builder
	Stdout = &bs
	flags := Flags{
		ConfigDir:      dir,
		LogLevel:       "debug",
		TestDiscipline: "test",
	}
	wait, _, err := entry(&flags)
	require.NoError(t, err)
	wait()
	require.Equal(t, `1.1.1.1
2.2.2.2
`, bs.String())
}

func TestFileNotExistsOK(t *testing.T) {
	dir := makeTestConfig(t, `
jail:
  - id: test
    type: echo
discipline:
  - id: test
    source: log
    jail: [test]
    files: [{{.dir}}/absent.txt]
    regexes: ['%(ip)']
    skip_when_file_not_exists: true
`)
	flags := Flags{
		ConfigDir: dir,
		LogLevel:  "debug",
	}
	wait, stop, err := entry(&flags)
	require.NoError(t, err)
	stop()
	wait()

	dir = makeTestConfig(t, `
jail:
  - id: test
    type: echo
discipline:
  - id: test
    source: log
    jail: [test]
    files: [{{.dir}}/absent.txt]
    regexes: ['%(ip)']
`)
	flags = Flags{
		ConfigDir: dir,
		LogLevel:  "debug",
	}
	wait, stop, err = entry(&flags)
	require.Error(t, err)
	if stop != nil {
		stop()
	}
	if wait != nil {
		wait()
	}
}
