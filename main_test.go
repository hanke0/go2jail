package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
)

func makeTestConfig(t *testing.T, content string) string {
	testSetStrictConfig(t)
	t.Helper()
	tpl, err := template.New(t.Name()).Parse(content)
	require.NoError(t, err)
	dir, err := os.MkdirTemp("", "go2jail-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	writeTestNft(t, dir)
	var s strings.Builder
	err = tpl.Execute(&s, map[string]string{
		"dir":    dir,
		"nftlog": filepath.Join(dir, "nft.log"),
		"Name":   t.Name(),
	})
	require.NoError(t, err)
	text := s.String()
	err = os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(text), 0777)
	require.NoError(t, err)
	return dir
}

func writeTestNft(t *testing.T, dir string) {
	t.Helper()
	nft := fmt.Sprintf(`#!/bin/bash
	echo "$@" >>"%s/nft.log"
	`, dir)
	err := os.WriteFile(filepath.Join(dir, "nft"), []byte(nft), 0777)
	require.NoError(t, err)
	path := os.Getenv("PATH")
	newpath := dir + ":" + path
	err = os.Setenv("PATH", newpath)
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Setenv("PATH", path)
	})
}

func testRunDaemon(t *testing.T,
	configContent, LinesContent, expect string) string {
	t.Helper()
	dir := makeTestConfig(t, configContent)
	nftlog := filepath.Join(dir, "nft.log")
	watchfile := filepath.Join(dir, "test.log")
	err := os.WriteFile(watchfile, nil, 0777)
	require.NoError(t, err)
	var opt runDaemonOption
	opt.ConfigDir = dir
	opt.LogLevel = "debug"
	wait, stop, err := runDaemon(&opt)
	require.NoError(t, err)

	script := fmt.Sprintf(`#!/bin/bash
cat >> %s <<'__EOF__'
%s
__EOF__
    `, watchfile, LinesContent)
	s, err := RunScript(
		script,
		&ScriptOption{},
	)
	require.NoError(t, err, s)
	for range 50 {
		_, err := os.Stat(nftlog)
		if err == nil {
			break
		}
		t.Logf("waiting for nft log: %s", err)
		if os.IsNotExist(err) {
			time.Sleep(time.Millisecond * 100)
			continue
		}
		stop()
		wait()
		t.Fatal(err)
	}
	t.Log("stopping...")
	stop()
	t.Log("waiting...")
	wait()
	t.Log("read nft log")
	b, err := os.ReadFile(nftlog)
	require.NoError(t, err)
	require.Equal(t, expect, string(b))
	return dir
}

func TestBasicLogAndNftReject(t *testing.T) {
	cfg := `
jails:
  - id: '{{.Name}}'
    type: nftset
    sudo: false # run nft command without sudo
    nft_executable: nft # nft executable path
    rule: inet # nft rule name
    table: filter # nft table name
    ipv4_set: ipv4_block_set # nft set name for ipv4
    ipv6_set: ipv6_block_set # nft set name for ipv6
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip)'
    rate: 1/1s
`
	lines := `1.1.1.1
2.2.2.2`
	expect := `add element inet filter ipv4_block_set { 1.1.1.1 }
add element inet filter ipv4_block_set { 2.2.2.2 }
`
	testRunDaemon(t, cfg, lines, expect)
}

func TestLogDisciplineRateWorks(t *testing.T) {
	cfg := `
jails:
  - id: '{{.Name}}'
    type: nftset
    sudo: false # run nft command without sudo
    nft_executable: nft # nft executable path
    rule: inet # nft rule name
    table: filter # nft table name
    ipv4_set: ipv4_block_set # nft set name for ipv4
    ipv6_set: ipv6_block_set # nft set name for ipv6
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip)'
    rate: 2/m
`
	lines := `1.1.1.1
1.1.1.1
2.2.2.2`
	expect := `add element inet filter ipv4_block_set { 1.1.1.1 }
`
	testRunDaemon(t, cfg, lines, expect)
}

func TestLogDisciplineIgnoreWorks(t *testing.T) {
	cfg := `
jails:
  - id: '{{.Name}}'
    type: nftset
    sudo: false # run nft command without sudo
    nft_executable: nft # nft executable path
    rule: inet # nft rule name
    table: filter # nft table name
    ipv4_set: ipv4_block_set # nft set name for ipv4
    ipv6_set: ipv6_block_set # nft set name for ipv6
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip)'
    ignores: '^1\.'
    rate: 1/1s
`
	lines := `1.1.1.1
1.1.1.1
2.2.2.2`
	expect := `add element inet filter ipv4_block_set { 2.2.2.2 }
`
	testRunDaemon(t, cfg, lines, expect)
}

func TestShellJailWorks(t *testing.T) {
	cfg := `
jails:
  - id: '{{.Name}}'
    type: shell
    run: |
      nft "$@"
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip)'
    rate: 1/s
`
	lines := `1.1.1.1
1.1.1.1
2.2.2.2`
	expect := `1.1.1.1 1.1.1.1
1.1.1.1 1.1.1.1
2.2.2.2 2.2.2.2
`
	testRunDaemon(t, cfg, lines, expect)
}

func TestShellEnvGroup(t *testing.T) {
	cfg := `
jails:
  - id: '{{.Name}}'
    type: shell
    run: |
      env | grep ^GO2JAIL | xargs nft "$1"
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip) (?P<user>.+)'
    rate: 1/s
`
	lines := `1.1.1.1 user1
1.1.1.1 user2
2.2.2.2 user3`
	expect := `1.1.1.1 GO2JAIL_ip=1.1.1.1 GO2JAIL_=1.1.1.1 user1 GO2JAIL_user=user1
1.1.1.1 GO2JAIL_ip=1.1.1.1 GO2JAIL_=1.1.1.1 user2 GO2JAIL_user=user2
2.2.2.2 GO2JAIL_ip=2.2.2.2 GO2JAIL_=2.2.2.2 user3 GO2JAIL_user=user3
`
	testRunDaemon(t, cfg, lines, expect)
}

func TestShellDiscipline(t *testing.T) {
	cfg := `
jails:
  - id: '{{.Name}}'
    type: shell
    run: |
      nft "$@"
watches:
  - id: '{{.Name}}'
    type: shell
    run: |
      echo 3.3.3.3
      echo 3.3.3.4
      echo 3.3.3.5
      echo 3.3.3.6
      exit 1
    restart_policy: 'on-success/10s'
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip)'
    rate: 1/s
`
	lines := ``
	expect := `3.3.3.3 3.3.3.3
3.3.3.4 3.3.3.4
3.3.3.5 3.3.3.5
3.3.3.6 3.3.3.6
`
	testRunDaemon(t, cfg, lines, expect)
}

func TestTestingWorks(t *testing.T) {
	dir := makeTestConfig(t, `
jails:
  - id: '{{.Name}}'
    type: echo
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: ['%(ip)']
    rate: 1/s
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
	var opt testDisciplineOption
	opt.ConfigDir = dir
	opt.LogLevel = "debug"
	wait, _, err := runTestDiscipline(&opt, t.Name())
	require.NoError(t, err)
	wait()
	require.Equal(t, `1.1.1.1 1.1.1.1
2.2.2.2 2.2.2.2
`, bs.String())
}

func TestFileNotExistsOK(t *testing.T) {
	dir := makeTestConfig(t, `
jails:
  - id: '{{.Name}}'
    type: echo
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/absent.log]
    skip_when_file_not_exists: true
disciplines:
  - id: test
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: ['%(ip)']
    rate: 1/s
`)
	var opt runDaemonOption
	opt.ConfigDir = dir
	opt.LogLevel = "debug"
	wait, stop, err := runDaemon(&opt)
	require.NoError(t, err)
	stop()
	wait()

	dir = makeTestConfig(t, `
jails:
  - id: '{{.Name}}'
    type: echo
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/absent.log]
disciplines:
  - id: test
    jails: ['{{.Name}}']
    watches: ['{{.Name}}']
    matches: ['%(ip)']
    rate: 1/s
`)
	opt.ConfigDir = dir
	opt.LogLevel = "debug"
	wait, stop, err = runDaemon(&opt)
	require.Error(t, err)
	if stop != nil {
		stop()
	}
	if wait != nil {
		wait()
	}
}
