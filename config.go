package main

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
)

type BaseJail struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
}

type Jail struct {
	BaseJail
	Action Jailer `yaml:"-"`
}

func (j *Jail) UnmarshalYAML(b []byte) error {
	if err := yaml.Unmarshal(b, &j.BaseJail); err != nil {
		return err
	}
	builder := jailProviders[j.Type]
	if builder == nil {
		return fmt.Errorf("unknown jail type: %s", j.Type)
	}
	p, err := builder(b)
	if err != nil {
		return err
	}
	j.Action = p
	return nil
}

type BaseDiscipline struct {
	ID     string   `yaml:"id"`
	Jail   []string `yaml:"jail"`
	Source string   `yaml:"source"`
}

type Discipline struct {
	BaseDiscipline
	Action Discipliner `yaml:"-"`
}

func (j *Discipline) UnmarshalYAML(b []byte) error {
	if err := yaml.Unmarshal(b, &j.BaseDiscipline); err != nil {
		return err
	}
	builder := disciplineProviders[j.Source]
	if builder == nil {
		return fmt.Errorf("unknown discipline source: %s", j.Source)
	}
	p, err := builder(b)
	if err != nil {
		return err
	}
	j.Action = p
	return nil
}

type Jailer interface {
	Arrest(ip net.IP, log Logger) error
	Close() error
}

type Discipliner interface {
	Watch(log Logger) (<-chan net.IP, error)
	Close() error
}

type (
	DisciplineBuilder = func([]byte) (Discipliner, error)
	JailBuilder       = func([]byte) (Jailer, error)
)

var (
	disciplineProviders = map[string]DisciplineBuilder{}
	jailProviders       = map[string]JailBuilder{}
)

func RegisterDiscipline(name string, bu DisciplineBuilder) {
	disciplineProviders[name] = bu
}

func RegisterJail(name string, bu JailBuilder) {
	jailProviders[name] = bu
}

type ipCidr struct {
	net.IPNet
}

func (i *ipCidr) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return err
	}
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("bad ipcidr: %s, %w", s, err)
	}
	i.IPNet = *cidr
	return nil
}

func (i ipCidr) Equal(o ipCidr) bool {
	return i.IP.Equal(o.IP) && i.Mask.String() == o.Mask.String()
}

type Config struct {
	Jail       []*Jail       `yaml:"jail"`
	Allow      []ipCidr      `yaml:"allow"`
	Discipline []*Discipline `yaml:"discipline"`
}

func (c *Config) AllowIP(ip net.IP) bool {
	for _, v := range c.Allow {
		if v.Contains(ip) {
			return true
		}
	}
	return false
}

func Parse(files ...string) (*Config, error) {
	var cfg Config
	for _, f := range files {
		c, err := parse(f)
		if err != nil {
			return nil, err
		}
		mergeConfig(&cfg, c)
	}
	return &cfg, nil
}

func parse(file string) (*Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("parse config fail %s: %w", file, err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config fail %s: %w", file, err)
	}
	return &cfg, nil
}

func mergeConfig(dst, src *Config) {
	dst.Jail = appendIf(dst.Jail, src.Jail, func(a, b *Jail) bool {
		return a.ID == b.ID
	})
	dst.Discipline = appendIf(dst.Discipline, src.Discipline, func(a, b *Discipline) bool {
		return a.ID == b.ID
	})
	dst.Allow = appendIf(dst.Allow, src.Allow, func(a, b ipCidr) bool {
		return a.Equal(b)
	})
}

func appendIf[T any](dst, src []T, eq func(a, b T) bool) []T {
LOOP:
	for _, j := range src {
		for i, e := range dst {
			if eq(j, e) {
				dst[i] = j
				continue LOOP
			}
		}
		dst = append(dst, j)
	}
	return dst
}
