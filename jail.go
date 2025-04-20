package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/goccy/go-yaml"
)

func init() {
	RegisterJail("nftset", NewNftJail)
	RegisterJail("echo", NewEchoJail)
	RegisterJail("log", NewEchoJail)
	RegisterJail("shell", NewShellJail)
}

type NftJail struct {
	ID            string `yaml:"id"`
	Sudo          bool   `yaml:"sudo"`
	NftExecutable string `yaml:"nft_executable"`
	Rule          string `yaml:"rule"`
	Table         string `yaml:"table"`
	IPv4Set       string `yaml:"ipv4_set"`
	IPv6Set       string `yaml:"ipv6_set"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewNftJail(b []byte) (Jailer, error) {
	var j NftJail
	if err := yaml.Unmarshal(b, &j); err != nil {
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
	if j.ID == "" {
		j.ID = randomString(8)
	}
	j.NftExecutable = p
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (nj *NftJail) Arrest(ip net.IP, log Logger) error {
	var (
		s   string
		set string
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
		log.Errorf("[jail-nft][%s] arrest ip %s: err=%v, program=%v output=%s", nj.ID, s, err, program, buf.String())
		nj.jailFailCounter.Incr()
	} else {
		log.Infof("[jail-nft][%s] arrest ip %s success", nj.ID, s)
		nj.jailSuccessCounter.Incr()
	}
	return err
}

func (nj *NftJail) Close() error {
	return nil
}

type EchoJail struct {
	ID                 string   `yaml:"id"`
	jailSuccessCounter *Counter `yaml:"-"`
}

func NewEchoJail(b []byte) (Jailer, error) {
	var j EchoJail
	if err := yaml.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if j.ID == "" {
		j.ID = randomString(8)
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

func (ej *EchoJail) Arrest(ip net.IP, log Logger) error {
	fmt.Fprintln(Stdout, ip.String())
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *EchoJail) Close() error {
	return nil
}

type LogJail struct {
	ID string `yaml:"id"`

	jailSuccessCounter *Counter `yaml:"-"`
}

func NewLogJail(b []byte) (Jailer, error) {
	var j LogJail
	err := yaml.Unmarshal(b, &j)
	if err != nil {
		return nil, err
	}
	if j.ID == "" {
		j.ID = randomString(8)
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	return &j, nil
}

func (ej *LogJail) Arrest(ip net.IP, log Logger) error {
	log.Errorf("[jail-echo][%s] arrest ip %s", ej.ID, ip)
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *LogJail) Close() error {
	return nil
}

type ShellJail struct {
	ID           string `yaml:"id"`
	Run          string `yaml:"run"`
	ScriptOption `yaml:",inline"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewShellJail(b []byte) (Jailer, error) {
	var j ShellJail
	if err := yaml.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if err := j.ScriptOption.SetupShell(); err != nil {
		return nil, err
	}
	if j.ID == "" {
		j.ID = randomString(8)
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (sj *ShellJail) Arrest(ip net.IP, log Logger) error {
	c, err := RunScript(sj.Run, &sj.ScriptOption, ip.String())
	if err != nil {
		log.Errorf("[jail-shell][%s] arrest ip %s fail: %v, %s", sj.ID, ip, err, c)
		sj.jailFailCounter.Incr()
	} else {
		log.Infof("[jail-shell][%s] arrest ip %s success", sj.ID, ip)
		sj.jailSuccessCounter.Incr()
	}
	return err
}

func (sj *ShellJail) Close() error {
	return nil
}
