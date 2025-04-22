package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func init() {
	RegisterJail("nftset", NewNftJail)
	RegisterJail("echo", NewEchoJail)
	RegisterJail("log", NewLogJail)
	RegisterJail("shell", NewShellJail)
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
	log.Errorf("[jail-echo][%s] arrest ip %s", ej.ID, bad.IP)
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *LogJail) Close() error {
	return nil
}

type ShellJail struct {
	BaseJail     `yaml:",inline"`
	Run          string `yaml:"run"`
	ScriptOption `yaml:",inline"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewShellJail(decode Decoder) (Jailer, error) {
	var j ShellJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	if err := j.ScriptOption.SetupShell(); err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (sj *ShellJail) Arrest(bad BadLog, log Logger) error {
	c, err := RunScript(sj.Run, &sj.ScriptOption, bad.IP.String(), bad.Line)
	if err != nil {
		log.Errorf("[jail-shell][%s] arrest ip %s fail: %v, %s", sj.ID, bad, err, c)
		sj.jailFailCounter.Incr()
	} else {
		log.Infof("[jail-shell][%s] arrest ip %s success", sj.ID, bad.IP)
		sj.jailSuccessCounter.Incr()
	}
	return err
}

func (sj *ShellJail) Close() error {
	return nil
}
