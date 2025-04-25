package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

func init() {
	RegisterJail("nftset", NewNftJail)
	RegisterJail("echo", NewEchoJail)
	RegisterJail("log", NewLogJail)
	RegisterJail("shell", NewShellJail)
	RegisterJail("http", NewHTTPJail)
}

type NftJail struct {
	BaseJail      `yaml:",inline"`
	Sudo          bool   `yaml:"sudo"`
	NftExecutable string `yaml:"nft_executable"`
	Rule          string `yaml:"rule"`
	Table         string `yaml:"table"`
	IPv4Set       string `yaml:"ipv4_set"`
	IPv6Set       string `yaml:"ipv6_set"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewNftJail(decode Decoder) (Jailer, error) {
	var j NftJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	nft := j.NftExecutable
	if nft == "" {
		nft = "nft"
	}
	p, err := exec.LookPath(nft)
	if err != nil {
		return nil, fmt.Errorf("can not find nft executable: %w", err)
	}
	j.NftExecutable = p
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (nj *NftJail) Arrest(bad BadLog, log Logger) error {
	var (
		s   string
		set string
		ip  = bad.IP
	)
	if ip.To4() != nil {
		s = ip.To4().String()
		set = nj.IPv4Set
	} else {
		s = ip.To16().String()
		set = nj.IPv6Set
	}
	var program []string
	if nj.Sudo {
		program = []string{"sudo"}
	}
	program = append(program,
		nj.NftExecutable,
		"add",
		"element",
		nj.Rule,
		nj.Table,
		set,
		"{",
		s,
		"}",
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	cmd := exec.CommandContext(ctx, program[0], program[1:]...)
	buf := NewRingBuffer(defaultScriptOutputSize)
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := cmd.Run()
	if err != nil {
		log.Errorf("[jail-%s] arrest ip %s: err=%v, program=%v output=%s", nj.ID, s, err, program, buf.String())
		nj.jailFailCounter.Incr()
	} else {
		log.Infof("[jail-%s] arrest ip %s success", nj.ID, s)
		nj.jailSuccessCounter.Incr()
	}
	return err
}

func (nj *NftJail) Close() error {
	return nil
}

type EchoJail struct {
	BaseJail           `yaml:",inline"`
	jailSuccessCounter *Counter `yaml:"-"`
}

func NewEchoJail(decode Decoder) (Jailer, error) {
	var j EchoJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	return &j, nil
}

var testDisciplineJail *Jail

func init() {
	var j Jail
	err := j.UnmarshalYAML([]byte(`id: test-config
type: echo`))
	if err != nil {
		panic(err)
	}
	testDisciplineJail = &j
}

func (ej *EchoJail) Arrest(bad BadLog, log Logger) error {
	fmt.Fprintln(Stdout, bad.IP.String(), bad.Line)
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *EchoJail) Close() error {
	return nil
}

type LogJail struct {
	BaseJail `yaml:",inline"`

	jailSuccessCounter *Counter `yaml:"-"`
}

func NewLogJail(decode Decoder) (Jailer, error) {
	var j LogJail
	err := decode(&j)
	if err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	return &j, nil
}

func (ej *LogJail) Arrest(bad BadLog, log Logger) error {
	log.Errorf("[jail-%s] arrest ip %s, groups=%s", ej.ID, bad.IP, bad.Extend.String())
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *LogJail) Close() error {
	return nil
}

type Options struct {
}

type ShellJail struct {
	BaseJail         `yaml:",inline"`
	Run              string `yaml:"run"`
	YAMLScriptOption `yaml:",inline"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewShellJail(decode Decoder) (Jailer, error) {
	var j ShellJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	if err := j.YAMLScriptOption.SetupShell(); err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (sj *ShellJail) Arrest(bad BadLog, log Logger) error {
	opt := ScriptOption{
		YAMLScriptOption: sj.YAMLScriptOption,
		Env:              bad.Extend.AsEnv(),
	}
	c, err := RunScript(sj.Run, &opt, bad.IP.String(), bad.Line)
	if err != nil {
		log.Errorf("[jail-%s] arrest ip %s fail: %v, %s", sj.ID, bad.IP, err, c)
		sj.jailFailCounter.Incr()
	} else {
		log.Infof("[jail-%s] arrest ip %s success", sj.ID, bad.IP)
		sj.jailSuccessCounter.Incr()
	}
	return err
}

func (sj *ShellJail) Close() error {
	return nil
}

type HTTPJail struct {
	BaseJail `yaml:",inline"`
	URL      string     `yaml:"http_url"`
	Method   string     `yaml:"http_method"`
	Args     []KeyValue `yaml:"http_args"`
	Headers  []KeyValue `yaml:"http_headers"`
	Body     string     `yaml:"http_body"`
}

func NewHTTPJail(decode Decoder) (Jailer, error) {
	var j HTTPJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	_, err := url.Parse(j.URL)
	if err != nil {
		return nil, err
	}
	if j.Method == "" {
		j.Method = http.MethodPost
	}
	return &j, nil
}

func (hj *HTTPJail) Arrest(bad BadLog, log Logger) error {
	log.Debugf("[jail-%s] start arrest ip %s", hj.ID, bad.IP)
	expander := func(s string) string {
		for _, entry := range bad.Extend {
			if entry.Key == s {
				return entry.Value
			}
		}
		return ""
	}
	body := os.Expand(hj.Body, expander)
	url := os.Expand(hj.URL, expander)
	req, err := http.NewRequest(hj.Method, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	for _, entry := range hj.Headers {
		req.Header.Add(entry.Key, os.Expand(entry.Value, expander))
	}
	query := req.URL.Query()
	for _, entry := range hj.Args {
		query.Add(entry.Key, os.Expand(entry.Value, expander))
	}
	req.URL.RawQuery = query.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body := io.LimitReader(resp.Body, 1024)
		b, _ := io.ReadAll(body)
		return fmt.Errorf("http status code %d, body=%s", resp.StatusCode, string(b))
	}
	log.Infof("[jail-%s] arrest ip %s success", hj.ID, bad.IP)
	return nil
}

func (hj *HTTPJail) Close() error {
	return nil
}
