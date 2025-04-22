package main

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/goccy/go-yaml"
)

type (
	WatchBuilder      = func(dec Decoder) (Watcher, error)
	JailBuilder       = func(dec Decoder) (Jailer, error)
	DisciplineBuilder = func(dec Decoder) (Discipliner, error)
)

var (
	watchProviders     = map[string]WatchBuilder{}
	jailProviders      = map[string]JailBuilder{}
	disciplineBuilders = map[string]DisciplineBuilder{}
)

func RegisterWatcher(name string, bu WatchBuilder) {
	watchProviders[name] = bu
}

func RegisterJail(name string, bu JailBuilder) {
	jailProviders[name] = bu
}

func RegisterDiscipliner(name string, bu DisciplineBuilder) {
	disciplineBuilders[name] = bu
}

type Line struct {
	WatchID string
	Text    string
}

func NewLine(watchID string, text string) Line {
	return Line{
		WatchID: watchID,
		Text:    text,
	}
}

type BaseWatch struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
}

type Watch struct {
	BaseWatch `yaml:",inline"`
	Action    Watcher `yaml:",inline"`
}

type Watcher interface {
	Watch(log Logger) (<-chan Line, error)
	Test(log Logger) (<-chan Line, error)
	Close() error
}

func (j *Watch) UnmarshalYAML(b []byte) error {
	if err := yaml.Unmarshal(b, &j.BaseWatch); err != nil {
		return err
	}
	if j.ID == "" {
		return errors.New("watch id is empty")
	}
	builder := watchProviders[j.Type]
	if builder == nil {
		return fmt.Errorf("unknown discipline type: %s", j.Type)
	}
	p, err := builder(NewYAMLDecoder(b))
	if err != nil {
		return err
	}
	j.Action = p
	return nil
}

type BadLog struct {
	Line         string
	WatchID      string
	DisciplineID string
	IP           net.IP
}

func NewBadLog(line Line, disciplineID string, ip net.IP) BadLog {
	return BadLog{
		Line:         line.Text,
		WatchID:      line.WatchID,
		DisciplineID: disciplineID,
		IP:           ip,
	}
}

type BaseJail struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
}

type Jail struct {
	BaseJail `yaml:",inline"`
	Action   Jailer `yaml:",inline"`
}

type Jailer interface {
	Arrest(data BadLog, log Logger) error
	Close() error
}

func (j *Jail) UnmarshalYAML(b []byte) error {
	if err := yaml.Unmarshal(b, &j.BaseJail); err != nil {
		return err
	}
	builder := jailProviders[j.Type]
	if builder == nil {
		return fmt.Errorf("unknown jail type: %s", j.Type)
	}
	p, err := builder(NewYAMLDecoder(b))
	if err != nil {
		return err
	}
	j.Action = p
	return nil
}

type Discipliner interface {
	Judge(line Line, allow Allows, logger Logger) (BadLog, bool)
	Close() error
}

type BaseDiscipline struct {
	ID      string  `yaml:"id"`
	Type    string  `yaml:"type"`
	Watches Strings `yaml:"watches"`
	Jails   Strings `yaml:"jails"`
}

type Discipline struct {
	BaseDiscipline `yaml:",inline"`
	Action         Discipliner `yaml:",inline"`
}

func (d *Discipline) UnmarshalYAML(b []byte) error {
	if err := yaml.Unmarshal(b, &d.BaseDiscipline); err != nil {
		return err
	}
	if d.ID == "" {
		return errors.New("watch id is empty")
	}
	if d.Type == "" {
		d.Type = "regex"
	}
	builder := disciplineBuilders[d.Type]
	if builder == nil {
		return fmt.Errorf("unknown discipline type: %s", d.Type)
	}
	p, err := builder(NewYAMLDecoder(b))
	if err != nil {
		return err
	}
	d.Action = p
	return nil
}

type Config struct {
	Jails       []*Jail       `yaml:"jails"`
	Watches     []*Watch      `yaml:"watches"`
	Disciplines []*Discipline `yaml:"disciplines"`
	Allows      Allows        `yaml:"allows"`
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
	for _, d := range cfg.Disciplines {
		for _, id := range d.Watches {
			if !slices.ContainsFunc(cfg.Watches, func(w *Watch) bool {
				return w.ID == id
			}) {
				return nil, fmt.Errorf("[discipline][%s] watch %s not found", d.ID, id)
			}
		}
		for _, id := range d.Jails {
			if !slices.ContainsFunc(
				cfg.Jails,
				func(j *Jail) bool { return j.ID == id },
			) {
				return nil, fmt.Errorf("[discipline][%s] jail %s not found", d.ID, id)
			}
		}
	}
	return &cfg, nil
}

func (c *Config) String() string {
	return YamlEncode(c)
}

func parse(file string) (*Config, error) {
	var cfg Config
	if err := YAMLDecodeFile(file, &cfg); err != nil {
		return nil, fmt.Errorf("parse config fail %s: %w", file, err)
	}
	return &cfg, nil
}

func mergeConfig(dst, src *Config) {
	dst.Jails = appendIf(dst.Jails, src.Jails, func(a, b *Jail) bool {
		return a.ID == b.ID
	})
	dst.Disciplines = appendIf(dst.Disciplines, src.Disciplines, func(a, b *Discipline) bool {
		return a.ID == b.ID
	})
	dst.Watches = appendIf(dst.Watches, src.Watches, func(a, b *Watch) bool {
		return a.ID == b.ID
	})
	dst.Allows = appendIf(dst.Allows, src.Allows, func(a, b net.IPNet) bool {
		return a.IP.Equal(b.IP) && a.Mask.String() == b.Mask.String()
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

type Allows []net.IPNet

func (a Allows) Contains(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsMulticast() {
		return true
	}
	for _, l := range a {
		if l.Contains(ip) {
			return true
		}
	}
	return false
}

func (a Allows) MarshalYAML() (any, error) {
	var ss []string
	for _, l := range a {
		ss = append(ss, l.String())
	}
	return ss, nil
}

func (a *Allows) UnmarshalYAML(b []byte) error {
	var ss []string
	if err := yaml.Unmarshal(b, &ss); err != nil {
		return err
	}
	for _, s := range ss {
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("bad ipcidr: %s, %w", s, err)
		}
		*a = appendIf(*a, []net.IPNet{*cidr}, func(a, b net.IPNet) bool {
			return a.IP.Equal(b.IP) && a.Mask.String() == b.Mask.String()
		})
	}
	return nil
}
