package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
)

func makeTestConfig(t *testing.T, content string, options ...string) string {
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
	m := map[string]string{
		"dir":    dir,
		"nftlog": filepath.Join(dir, "nft.log"),
		"Name":   t.Name(),
	}
	for i := 0; i < len(options); i += 2 {
		m[options[i]] = options[i+1]
	}
	err = tpl.Execute(&s, m)
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

var testStatAddr string

func init() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	testStatAddr = ln.Addr().String()
	if err := ln.Close(); err != nil {
		panic(err)
	}
}

func testStartDaemon(t *testing.T,
	configContent, LinesContent string, options ...string) (wait, stop func(), dir string) {
	t.Helper()
	dir = makeTestConfig(t, configContent, options...)
	watchfile := filepath.Join(dir, "test.log")
	err := os.WriteFile(watchfile, nil, 0777)
	require.NoError(t, err)
	var opt runDaemonOption
	opt.ConfigDir = dir
	opt.LogLevel = "debug"
	opt.HTTPStatsListenAddr = testStatAddr
	globalCounters.Clear()
	wait, stop, err = runDaemon(&opt)
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
	return wait, stop, dir
}

func testWaitNftLogWrite(t *testing.T, dir string) string {
	nftlog := filepath.Join(dir, "nft.log")
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
		t.Fatal(err)
	}
	return nftlog
}

func testRunDaemon(t *testing.T,
	configContent, LinesContent, expect string, options ...string) string {
	wait, stop, dir := testStartDaemon(t, configContent, LinesContent, options...)
	nftlog := testWaitNftLogWrite(t, dir)
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

func TestCountersWorks(t *testing.T) {
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
0.0.0.0
2.2.2.2`
	expect := `add element inet filter ipv4_block_set { 1.1.1.1 }
add element inet filter ipv4_block_set { 2.2.2.2 }
`
	wait, stop, dir := testStartDaemon(t, cfg, lines)
	nftlog := testWaitNftLogWrite(t, dir)
	var bs bytes.Buffer
	err := OutputCounters(&bs)
	require.NoError(t, err)
	t.Log("stopping...")
	stop()
	t.Log("waiting...")
	wait()
	t.Log("read nft log")
	b, err := os.ReadFile(nftlog)
	require.NoError(t, err)
	require.Equal(t, expect, string(b))

	var d map[string]map[string]map[string]int
	err = json.Unmarshal(bs.Bytes(), &d)
	require.NoError(t, err)
	testEqual := func(group, id, name string, expect int) {
		t.Helper()
		v, ok := d[group][id][name]
		require.True(t, ok, bs.String())
		require.Equal(t, expect, v, "%s-%s-%s, json=%s", group, id, name, bs.String())
	}

	testEqual("watch", t.Name(), "lines", 3)
	testEqual("discipline", t.Name(), "tail_lines", 3)
	testEqual("discipline", t.Name(), "match_lines", 3)
	testEqual("discipline", t.Name(), "bad_ip", 0)
	testEqual("discipline", t.Name(), "allow_ip", 1)
	testEqual("discipline", t.Name(), "watch_ip", 0)
	testEqual("discipline", t.Name(), "arrest_ip", 2)
	testEqual("jail", t.Name(), "success", 2)
	testEqual("jail", t.Name(), "fail", 0)
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
	u, err := user.Current()
	require.NoError(t, err)
	require.NotEqual(t, "", u.Username)
	testRunDaemon(t, cfg, lines, expect, "user", u.Username)
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
	expect := `1.1.1.1 GO2JAIL_ip=1.1.1.1 GO2JAIL_=1.1.1.1 user1 GO2JAIL_user=user1 GO2JAIL_IP_LOCATION=-
1.1.1.1 GO2JAIL_ip=1.1.1.1 GO2JAIL_=1.1.1.1 user2 GO2JAIL_user=user2 GO2JAIL_IP_LOCATION=-
2.2.2.2 GO2JAIL_ip=2.2.2.2 GO2JAIL_=2.2.2.2 user3 GO2JAIL_user=user3 GO2JAIL_IP_LOCATION=-
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

func TestHTTPJailWorks(t *testing.T) {
	var requests []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		request := r.Clone(context.Background())
		request.Body = io.NopCloser(bytes.NewReader(body))
		requests = append(requests, request)
	}))
	t.Cleanup(server.Close)

	cfg := `
jails:
  - id: 'http{{.Name}}'
    type: http
    method: POST
    args:
        - key: user
          value: '${user}'
        - key: ip
          value: '${ip}'
        - key: some
          value: 'some'
    body: '${ip} ${user}'
    headers:
      - key: X-GO2JAIL
        value: '${user}'
    url: '{{.url}}/${ip}'
  - id: 'nft{{.Name}}'
    type: shell
    run: |
      nft "$1"
watches:
  - id: '{{.Name}}'
    type: file
    files: [{{.dir}}/test.log]
disciplines:
  - id: '{{.Name}}'
    jails: ['http{{.Name}}','nft{{.Name}}']
    watches: ['{{.Name}}']
    matches: '%(ip) (?P<user>.+)'
    rate: 1/s
`
	lines := `1.1.1.1 user1
2.2.2.2 user2
`
	expect := `1.1.1.1
2.2.2.2
`
	testRunDaemon(t, cfg, lines, expect, "url", server.URL)
	require.Len(t, requests, 2)
	for i, req := range requests {
		user := fmt.Sprintf("user%d", i+1)
		ip := fmt.Sprintf("%[1]d.%[1]d.%[1]d.%[1]d", i+1)
		bbody, _ := io.ReadAll(req.Body)
		body := string(bbody)
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "/"+ip, req.URL.Path)
		require.Equal(t, ip, req.URL.Query().Get("ip"))
		require.Equal(t, user, req.URL.Query().Get("user"))
		require.Equal(t, "some", req.URL.Query().Get("some"))
		require.Equal(t, user, req.Header.Get("X-GO2JAIL"))
		require.Equal(t, ip+" "+user, body)
	}
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
