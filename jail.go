package main

import (
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/stretchr/testify/assert/yaml"
)

func init() {
	RegisterJail("nftset", NewNftJail)
	RegisterJail("echo", NewEchoJail)
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
	j.NftExecutable = p
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
	f, err := Execute(ExecuteOptions{
		Program:    program,
		OutputSize: 1024,
		Timeout:    time.Second * 5,
	})
	if err != nil {
		log.Errorf("[jail-nft][%s] arrest ip %s: err=%v, output=%s", nj.ID, s, err, f)
	}
	return err
}

func (nj *NftJail) Close() error {
	return nil
}

type EchoJail struct {
	ID string `yaml:"id"`
}

func NewEchoJail(b []byte) (Jailer, error) {
	return &EchoJail{}, nil
}

func (ej *EchoJail) Arrest(ip net.IP, log Logger) error {
	log.Errorf("[jail-echo][%s] arrest ip %s", ej.ID, ip)
	return nil
}

func (ej *EchoJail) Close() error {
	return nil
}

type ShellJail struct {
	ID      string   `yaml:"id"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

func NewShellJail(b []byte) (Jailer, error) {
	var j ShellJail
	if err := yaml.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	cmd, err := exec.LookPath(j.Command)
	if err != nil {
		return nil, err
	}
	j.Command = cmd
	return &j, nil
}

func (sj *ShellJail) Arrest(ip net.IP, log Logger) error {
	program := append([]string{sj.Command}, sj.Args...)
	if sj.Args == nil {
		program = append(program, ip.String())
	}
	for i, arg := range program {
		switch arg {
		case "%(ip)":
			program[i] = ip.String()
		default:
		}
	}
	c, err := Execute(ExecuteOptions{
		Program:    program,
		OutputSize: 1024,
	})
	if err != nil {
		log.Errorf("[jail-shell][%s] arrest ip %s fail: %v, %s", sj.ID, ip, err, c)
	}
	return err
}

func (sj *ShellJail) Close() error {
	return nil
}
