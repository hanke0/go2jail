package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

type (
	WatchBuilder      = func(dec Decoder) (Watcher, error)
	JailBuilder       = func(dec Decoder) (Jailer, error)
	DisciplineBuilder = func(dec Decoder) (Discipliner, error)
)

var (
	watchProviders      = map[string]WatchBuilder{}
	jailProviders       = map[string]JailBuilder{}
	disciplineProviders = map[string]DisciplineBuilder{}
)

func RegisterWatcher(name string, bu WatchBuilder) {
	watchProviders[name] = bu
}

func RegisterJail(name string, bu JailBuilder) {
	jailProviders[name] = bu
}

func RegisterDiscipliner(name string, bu DisciplineBuilder) {
	disciplineProviders[name] = bu
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

type KeyValue struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type KeyValueList []KeyValue

func (k KeyValueList) Get(key string) string {
	for _, kv := range k {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

var envRegex = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

func (k KeyValueList) AsEnv() []string {
	var ss []string
	for _, v := range k {
		k := envRegex.ReplaceAllString(v.Key, "_")
		ss = append(ss, fmt.Sprintf(
			"GO2JAIL_%s=%s", k, v.Value,
		))
	}
	return ss
}

func (k KeyValueList) String() string {
	var bs strings.Builder
	for _, v := range k {
		if bs.Len() > 0 {
			bs.WriteByte('\t')
		}
		bs.WriteString(v.Key)
		bs.WriteByte('=')
		bs.WriteString(v.Value)
	}
	return bs.String()
}

type BadLog struct {
	Line         string
	WatchID      string
	DisciplineID string
	IP           net.IP
	Extend       KeyValueList
	IPLocation   string
}

func NewBadLog(line Line, disciplineID string, ip net.IP, extend ...KeyValue) BadLog {
	return BadLog{
		Line:         line.Text,
		WatchID:      line.WatchID,
		DisciplineID: disciplineID,
		IP:           ip,
		Extend:       extend,
	}
}

func (b *BadLog) AsEnv() []string {
	envs := b.Extend.AsEnv()
	envs = append(envs, fmt.Sprintf("GO2JAIL_IP_LOCATION=%s", b.IPLocation))
	return envs
}

func (b *BadLog) Mapping(s string) string {
	switch s {
	case "ip":
		return b.IP.String()
	case "ip_location":
		return b.IPLocation
	default:
		return b.Extend.Get(s)
	}
}

type BaseJail struct {
	ID         string `yaml:"id"`
	Type       string `yaml:"type"`
	Background bool   `yaml:"background"`
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
	builder := disciplineProviders[d.Type]
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
	Jails             []*Jail           `yaml:"jails"`
	Watches           []*Watch          `yaml:"watches"`
	Disciplines       []*Discipline     `yaml:"disciplines"`
	Allows            Allows            `yaml:"allows"`
	IPLocationSources IPLocationSources `yaml:"ip_location_sources"`
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
				return nil, fmt.Errorf("[discipline-%s] watch %s not found", d.ID, id)
			}
		}
		for _, id := range d.Jails {
			if !slices.ContainsFunc(
				cfg.Jails,
				func(j *Jail) bool { return j.ID == id },
			) {
				return nil, fmt.Errorf("[discipline-%s] jail %s not found", d.ID, id)
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
	dst.IPLocationSources = appendIf(dst.IPLocationSources, src.IPLocationSources, func(a, b *IPLocationSource) bool {
		return a.ID == b.ID
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
	if ip.IsLoopback() || ip.IsUnspecified() {
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
