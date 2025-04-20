package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
)

type RingBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		buf: make([]byte, 0, size),
	}
}

func (b *RingBuffer) Bytes() []byte {
	return b.buf
}

func (b *RingBuffer) String() string {
	return string(b.buf)
}

func (r *RingBuffer) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(b) >= cap(r.buf) {
		copy(r.buf[:cap(r.buf)], b[len(b)-cap(r.buf):])
		r.buf = r.buf[:cap(r.buf)]
		return len(b), nil
	}
	free := cap(r.buf) - len(r.buf)
	if free >= len(b) {
		w := len(r.buf) + len(b)
		copy(r.buf[len(r.buf):w], b)
		r.buf = r.buf[:w]
		return len(b), nil
	}
	w := cap(r.buf) - len(b)
	cur := len(r.buf)
	r.buf = r.buf[:cap(r.buf)]
	copy(r.buf, r.buf[cur-w:cur])
	copy(r.buf[w:], b)
	return len(b), nil
}

type ScriptOption struct {
	Timeout      time.Duration `yaml:"timeout"`
	Shell        string        `yaml:"shell"`
	ShellOptions []string      `yaml:"shell_options"`

	Output        io.Writer `yaml:"-"`
	DiscardOutput bool      `yaml:"-"`
}

var (
	scriptTempDirectory string
)

func init() {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	scriptTempDirectory = filepath.Join(os.TempDir(), fmt.Sprintf("%s(%s)", u.Uid, u.Username))
	if strings.HasPrefix(scriptTempDirectory, "-") {
		panic(fmt.Sprintf("invalid scriptTempDirectory: %s", scriptTempDirectory))
	}
	err = os.MkdirAll(scriptTempDirectory, 0755)
	if err != nil {
		panic(err)
	}
}

func (s *ScriptOption) SetupShell() error {
	if s.Shell == "" {
		f, err := exec.LookPath("bash")
		if err != nil {
			f, err = exec.LookPath("sh")
			if err != nil {
				return fmt.Errorf("can not find shell: bash or sh %w", err)
			}
		}
		s.Shell = f
		s.ShellOptions = []string{"-e"}
		return nil
	}
	switch s.Shell {
	case "bash", "sh":
		if s.ShellOptions == nil {
			s.ShellOptions = []string{"-e"}
		}
	}
	f, err := exec.LookPath(s.Shell)
	if err != nil {
		return fmt.Errorf("can not find shell: %s %w", s.Shell, err)
	}
	s.Shell = f
	return nil
}

const defaultRunShellOutputSize = 4096

func NewShell(script string, opt *ScriptOption, args ...string) (*exec.Cmd, func(), error) {
	if err := opt.SetupShell(); err != nil {
		return nil, nil, err
	}
	hashsum := sha1.Sum([]byte(script))
	scriptfile := filepath.Join(
		scriptTempDirectory,
		hex.EncodeToString(hashsum[:]),
	)
	if stat, err := os.Stat(scriptfile); err != nil || stat.IsDir() {
		if err := os.WriteFile(scriptfile, []byte(script), 0750); err != nil {
			return nil, nil, fmt.Errorf("write tmp script file %s: %w", scriptfile, err)
		}
	}
	var t = opt.Timeout
	if t == 0 {
		t = time.Second * 60
	}
	cmds := make([]string, len(opt.ShellOptions)+1+len(args))
	copy(cmds, opt.ShellOptions)
	cmds[len(opt.ShellOptions)] = scriptfile
	copy(cmds[len(opt.ShellOptions)+1:], args)

	ctx, cancel := context.WithTimeout(context.Background(), t)
	cmd := exec.CommandContext(ctx, opt.Shell, cmds...)
	if opt.DiscardOutput {
		cmd.Stdout = nil
		cmd.Stderr = nil
	} else if opt.Output != nil {
		cmd.Stdout = opt.Output
		cmd.Stderr = cmd.Stdout
	} else {
		buf := NewRingBuffer(defaultRunShellOutputSize)
		cmd.Stdout = buf
		cmd.Stderr = cmd.Stdout
	}
	return cmd, cancel, nil
}

func RunShell(script string, opt *ScriptOption, args ...string) (string, error) {
	cmd, cancel, err := NewShell(script, opt, args...)
	defer cancel()
	if err != nil {
		return "", err
	}
	err = cmd.Run()
	if err != nil {
		return "", err
	}
	if os.Stdout != nil && cmd.Stderr == cmd.Stdout {
		b, ok := cmd.Stdout.(*RingBuffer)
		if ok {
			return string(b.Bytes()), nil
		}
	}
	return "", nil
}

type counterStats struct {
	n          int
	expiration time.Time
}

type Limiter struct {
	max     int
	timeout time.Duration
	mu      sync.Mutex
	wg      sync.WaitGroup
	mp      map[string]*counterStats
	cancel  func()
}

func (c *Limiter) String() string {
	if c == nil {
		return "1/s"
	}
	return fmt.Sprintf("%d/%s", c.max, formatDuration(c.timeout))
}

func (c *Limiter) MarshalYAML() (any, error) {
	return c.String(), nil
}

func (c *Limiter) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return err
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return fmt.Errorf("bad rate: %s", s)
	}
	max, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf("bad rate: %s", s)
	}
	d := strings.TrimSpace(parts[1])
	if !strings.ContainsAny(d, "0123456789") {
		d = "1" + d
	}
	timeout, err := time.ParseDuration(d)
	if err != nil || timeout < time.Millisecond {
		return fmt.Errorf("bad rate: %s", s)
	}
	c.max = max
	c.timeout = timeout
	return nil
}

func (c *Limiter) startBackground() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(1)
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				tick.Stop()
				c.wg.Done()
				return
			case <-tick.C:
				c.mu.Lock()
				for k, v := range c.mp {
					if v.expiration.Before(time.Now()) {
						delete(c.mp, k)
					}
				}
				c.mu.Unlock()
			}

		}
	}()
}

func (c *Limiter) Add(s string) (string, bool) {
	if c == nil {
		return "1/s", true
	}
	if c.timeout == 0 {
		c.timeout = time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel == nil {
		c.startBackground()
	}
	if c.mp == nil {
		c.mp = map[string]*counterStats{}
	}
	v := c.mp[s]
	if v == nil || v.expiration.Before(time.Now()) {
		v = &counterStats{
			n:          0,
			expiration: time.Now().Add(c.timeout),
		}
		c.mp[s] = v
	}
	v.n++
	ts := formatDuration(c.timeout)
	if v.n >= c.max {
		return fmt.Sprintf("%d/%s>=%d/%s", v.n, ts, c.max, ts), true
	}
	return fmt.Sprintf("%d/%s<%d/%s", v.n, ts, c.max, ts), false
}

func formatDuration(d time.Duration) string {
	if d.Seconds() < 0 {
		m := d.Milliseconds()
		return fmt.Sprintf("%dms", m)
	}
	if d == time.Second {
		return "s"
	}
	if d == time.Millisecond {
		return "ms"
	}
	if d == time.Minute {
		return "m"
	}
	if d == time.Hour {
		return "h"
	}
	if d == time.Hour*24 {
		return "d"
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		return s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m0s") {
		return s[:len(s)-4]
	}
	return s
}

func (c *Limiter) Stop() {
	if c == nil {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	raw() *log.Logger
}

type logger struct {
	log   *log.Logger
	level int
}

const (
	LevelDebug = 1 + iota
	LevelInfo
	LevelWarning
	LevelError
)

func NewLogger(level int, output io.Writer) Logger {
	l := logger{
		log:   log.New(output, "", log.Ltime|log.Ldate|log.Lshortfile),
		level: level,
	}
	return &l
}

func (l *logger) raw() *log.Logger {
	return l.log
}

func (l *logger) Debugf(format string, args ...interface{}) {
	if l.level > LevelDebug {
		return
	}
	l.log.Output(3, "[DEBUG] "+fmt.Sprintf(format, args...))
}

func (l *logger) Infof(format string, args ...interface{}) {
	if l.level > LevelInfo {
		return
	}
	l.log.Output(3, "[INFO] "+fmt.Sprintf(format, args...))
}

func (l *logger) Errorf(format string, args ...interface{}) {
	if l.level > LevelError {
		return
	}
	l.log.Output(3, "[ERROR] "+fmt.Sprintf(format, args...))
}

type Chan[T any] struct {
	ch     chan T
	closed bool
	once   sync.Once
}

func NewChan[T any](size int) *Chan[T] {
	return &Chan[T]{
		ch: make(chan T, size),
	}
}

func (c *Chan[T]) Close() {
	c.once.Do(func() {
		close(c.ch)
		c.closed = true
	})
}

func (c *Chan[T]) Send(v T) (err error) {
	if c.closed {
		return errors.New("send to closed channel")
	}
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("send panic: %v", e)
		}
	}()
	c.ch <- v
	return nil
}

func (c *Chan[T]) Reader() <-chan T {
	return c.ch
}

type Cleaner struct {
	cleans []func()
}

func (c *Cleaner) Prepend(f func()) {
	c.cleans = append([]func(){f}, c.cleans...)
}

func (c *Cleaner) Push(f func()) {
	c.cleans = append(c.cleans, f)
}

func (c *Cleaner) Clean() {
	for i := len(c.cleans) - 1; i >= 0; i-- {
		c.cleans[i]()
	}
}

func (c *Cleaner) Len() int {
	return len(c.cleans)
}

type Counter struct {
	name string
	n    atomic.Int64
}

func NewCounter(name string) *Counter {
	return &Counter{
		name: name,
	}
}

func (c *Counter) Incr() {
	c.n.Add(1)
}

func (c *Counter) Value() int64 {
	return c.n.Load()
}

func (c *Counter) Name() string {
	return c.name
}

var counters sync.Map

func RegisterCounter(c *Counter) {
	counters.Store(c.Name(), c)
}

func RegisterNewCounter(name string) *Counter {
	c := NewCounter(name)
	RegisterCounter(c)
	return c
}

func OutputCounters(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	data := map[string]int64{}
	counters.Range(func(k, v any) bool {
		c := v.(*Counter)
		data[c.Name()] = c.Value()
		return true
	})
	return enc.Encode(data)
}

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(rand.Intn(26))
	}
	return string(b)
}

type Matcher struct {
	regexes      []*regexp.Regexp
	expectGroups []int
}

func (m *Matcher) ExpectGroups(groups ...string) error {
	for _, group := range groups {
		for _, r := range m.regexes {
			gidx := -1
			for i, name := range r.SubexpNames() {
				if name == group {
					gidx = i
					break
				}
			}
			if gidx < 0 {
				return fmt.Errorf("regex group %q must exists", group)
			}
			m.expectGroups = append(m.expectGroups, gidx)
		}
	}
	return nil
}

var (
	regexReplacer = strings.NewReplacer(
		"%(ip)", `(?P<ip>(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})|([0-9]{1,3}(\.[0-9]{1,3}){3}))`,
	)
)

func (m *Matcher) MarshalYAML() (any, error) {
	var s []string
	for _, r := range m.regexes {
		s = append(s, r.String())
	}
	return s, nil
}

func (m *Matcher) UnmarshalYAML(b []byte) error {
	var reList []string
	if err := yaml.Unmarshal(b, &reList); err != nil {
		var s string
		if err1 := yaml.Unmarshal(b, &s); err1 != nil {
			return err
		}
		reList = []string{s}
	}
	for _, s := range reList {
		r, err := regexp.Compile(regexReplacer.Replace(s))
		if err != nil {
			return err
		}
		m.regexes = append(m.regexes, r)
	}
	return nil
}

func (m *Matcher) Test(s string) bool {
	return len(m.Match(s)) > 0
}

func (m *Matcher) Match(s string) []string {
	for _, r := range m.regexes {
		match := r.FindStringSubmatch(s)
		if len(match) > 0 {
			var groups = []string{match[0]}
			for _, idx := range m.expectGroups {
				if len(match) <= idx {
					continue
				}
				groups = append(groups, match[idx])
			}
			return groups
		}
	}
	return nil
}

func YamlEncode(v any) string {
	b, _ := yaml.MarshalWithOptions(v,
		yaml.IndentSequence(true),
		yaml.UseSingleQuote(true),
		yaml.WithSmartAnchor(),
	)
	return string(b)
}
