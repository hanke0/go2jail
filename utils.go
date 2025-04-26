package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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

type YAMLScriptOption struct {
	Timeout      time.Duration `yaml:"timeout,omitempty"`
	Shell        string        `yaml:"shell,omitempty"`
	ShellOptions []string      `yaml:"shell_options,omitempty"`
	ShellOutput  string        `yaml:"shell_output,omitempty"`
	RunUser      string        `yaml:"run_user,omitempty"`
	RunGroup     string        `yaml:"run_group,omitempty"`
}

type ScriptOption struct {
	YAMLScriptOption `yaml:"-"`

	ForceOutput io.Writer `yaml:"-"`
	Env         []string  `yaml:"-"`
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

func (s *YAMLScriptOption) SetupShell() error {
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

const defaultScriptOutputSize = 4096

var setCmdUserAndGroup = func(cmd *exec.Cmd, user, group string) error {
	return fmt.Errorf("change run user is not supported in platform: %s", runtime.GOOS)
}

func NewScript(script string, opt *ScriptOption, args ...string) (*exec.Cmd, func(), error) {
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

	var (
		ctx    context.Context
		cancel func()
	)
	if t > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), t)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	var cleaner Finisher
	cleaner.Push(cancel)
	cmd := exec.CommandContext(ctx, opt.Shell, cmds...)
	cmd.Dir = os.TempDir()
	if opt.RunUser != "" {
		if err := setCmdUserAndGroup(cmd, opt.RunUser, opt.RunGroup); err != nil {
			cleaner.Finish()
			return nil, nil, err
		}
	}
	switch {
	case opt.ForceOutput != nil:
		cmd.Stdout = opt.ForceOutput
		cmd.Stderr = opt.ForceOutput
	case opt.ShellOutput == "/dev/null":
		cmd.Stdout = nil
		cmd.Stderr = nil
	case opt.ShellOutput != "":
		f, err := os.OpenFile(opt.ShellOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			cleaner.Finish()
			return nil, nil, fmt.Errorf("open shell output file %s: %w", opt.ShellOutput, err)
		}
		cmd.Stdout = f
		cmd.Stderr = f
		cleaner.Push(func() {
			f.Close()
		})
	default:
		buf := NewRingBuffer(defaultScriptOutputSize)
		cmd.Stdout = buf
		cmd.Stderr = cmd.Stdout
	}
	cmd.Env = slices.Clone(opt.Env)
	for _, name := range inheritEnv {
		if !slices.ContainsFunc(cmd.Env, func(e string) bool {
			return strings.HasPrefix(e, name+"=")
		}) {
			v, ok := os.LookupEnv(name)
			if ok {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", name, v))
			}
		}
	}
	return cmd, cleaner.Finish, nil
}

var inheritEnv = []string{
	"TZ", "PATH", "HOME", "LANG",
	"LC_COLLATE", "LC_CTYPE", "LC_MONETARY", "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_ALL",
}

func RunScript(script string, opt *ScriptOption, args ...string) (string, error) {
	cmd, cancel, err := NewScript(script, opt, args...)
	if err != nil {
		return "", err
	}
	return RunCmd(cmd, cancel)

}

func RunCmd(cmd *exec.Cmd, cancel func()) (string, error) {
	defer cancel()
	err := cmd.Run()
	var out string
	if os.Stdout != nil {
		b, ok := cmd.Stdout.(*RingBuffer)
		if ok {
			out = b.String()
		}
	}
	return out, err
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
		c.mp = nil
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
	l.log.Output(2, "[DEBUG] "+fmt.Sprintf(format, args...))
}

func (l *logger) Infof(format string, args ...interface{}) {
	if l.level > LevelInfo {
		return
	}
	l.log.Output(2, "[INFO] "+fmt.Sprintf(format, args...))
}

func (l *logger) Errorf(format string, args ...interface{}) {
	if l.level > LevelError {
		return
	}
	l.log.Output(2, "[ERROR] "+fmt.Sprintf(format, args...))
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

type Finisher struct {
	cleans []func()
}

func (c *Finisher) Prepend(f func()) {
	c.cleans = append([]func(){f}, c.cleans...)
}

func (c *Finisher) Push(f func()) {
	c.cleans = append(c.cleans, f)
}

func (c *Finisher) Finish() {
	for i := len(c.cleans) - 1; i >= 0; i-- {
		c.cleans[i]()
	}
}

func (c *Finisher) Len() int {
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

type Matcher struct {
	regexList []*regexp.Regexp
}

func (m *Matcher) ExpectGroups(groups ...string) error {
	for _, group := range groups {
		for _, r := range m.regexList {
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
	for _, r := range m.regexList {
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
		m.regexList = append(m.regexList, r)
	}
	return nil
}

func (m *Matcher) Test(s string) bool {
	return len(m.Match(s)) > 0
}

func (m *Matcher) Match(s string) KeyValueList {
	for _, r := range m.regexList {
		match := r.FindStringSubmatch(s)
		if len(match) > 0 {
			var groups = KeyValueList{{Value: match[0]}}
			for i, name := range r.SubexpNames() {
				if name == "" {
					continue
				}
				groups = append(groups, KeyValue{
					Key:   name,
					Value: match[i],
				})
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

type chanWriter struct {
	ch  *Chan[string]
	buf []byte
}

func ChanWriter(ch *Chan[string]) io.WriteCloser {
	return &chanWriter{
		ch: ch,
	}
}

func (w *chanWriter) Close() error {
	if len(w.buf) > 0 {
		w.ch.Send(string(w.buf))
	}
	return nil
}

func (w *chanWriter) Write(p []byte) (n int, err error) {
	size := len(p)
	for len(p) > 0 {
		if idx := bytes.IndexByte(p, '\n'); idx > -1 {
			w.buf = append(w.buf, p[:idx]...)
			if err := w.ch.Send(string(w.buf)); err != nil {
				return size - len(p), err
			}
			p = p[idx+1:]
			w.buf = w.buf[:0]
			continue
		}
		w.buf = append(w.buf, p...)
		break
	}
	if len(w.buf) >= 24*1024 {
		w.ch.Send(string(w.buf))
		w.buf = w.buf[:0]
	}
	return size, nil
}

type RestartPolicy struct {
	raw        string
	started    *atomic.Bool
	always     bool
	exitOnFail bool
	times      int
	notFirst   bool
	backoff    time.Duration
}

func (rp *RestartPolicy) Stop() {
	rp.started.Store(false)
}

func (rp *RestartPolicy) String() string {
	return rp.raw
}

func (rp RestartPolicy) MarshalYAML() (any, error) {
	return rp.raw, nil
}

func (rp *RestartPolicy) UnmarshalYAML(b []byte) error {
	var (
		s      string
		policy string
	)
	if err := yaml.Unmarshal(b, &s); err != nil {
		return err
	}
	parts := strings.SplitN(s, "/", 2)
	policy = parts[0]
	if len(parts) > 1 {
		d, err := time.ParseDuration(parts[1])
		if err != nil {
			return fmt.Errorf("bad backoff: %s, %w", s, err)
		}
		rp.backoff = d
	}
	switch policy {
	case "always":
		rp.always = true
	case "on-success":
		rp.exitOnFail = true
	case "once":
		rp.times = 1
	default:
		return fmt.Errorf("bad policy: %s", s)
	}
	rp.raw = s
	rp.started = &atomic.Bool{}
	rp.started.Store(true)
	return nil
}

func (rp *RestartPolicy) wait() {
	if rp.backoff > 0 {
		if rp.notFirst {
			time.Sleep(rp.backoff)
		} else {
			rp.notFirst = true
		}
	}
}

func (rp *RestartPolicy) Next(err error) bool {
	if rp.started == nil || !rp.started.Load() {
		return false
	}
	if rp.always {
		rp.wait()
		return true
	}
	if rp.exitOnFail {
		return err == nil
	}
	if rp.times > 0 {
		rp.times--
		rp.wait()
		return true
	}
	return false
}

type Strings []string

func (s *Strings) UnmarshalYAML(b []byte) error {
	var ss []string
	if err := yaml.Unmarshal(b, &ss); err != nil {
		var s string
		if err1 := yaml.Unmarshal(b, &s); err1 != nil {
			return err
		}
		ss = []string{s}
	}
	*s = ss
	return nil
}

var YAMLStrict bool

func YamlDecode(b []byte, v any) error {
	if YAMLStrict {
		return yaml.UnmarshalWithOptions(b, v, yaml.Strict())
	}
	return yaml.Unmarshal(b, v)
}

func YAMLDecodeFile(file string, v any) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if YAMLStrict {
		return yaml.NewDecoder(f, yaml.Strict()).Decode(v)
	}
	return yaml.NewDecoder(f).Decode(v)
}

type Decoder func(v any) error

func NewYAMLDecoder(b []byte) Decoder {
	return func(v any) error {
		return YamlDecode(b, v)
	}
}

type HTTPHelper struct {
	URL     string        `yaml:"url"`
	Method  string        `yaml:"method"`
	Args    []KeyValue    `yaml:"args"`
	Headers []KeyValue    `yaml:"headers"`
	Body    string        `yaml:"body"`
	Timeout time.Duration `yaml:"timeout"`
}

func (h *HTTPHelper) Init(defaultMethod string) error {
	_, err := url.Parse(h.URL)
	if err != nil {
		return fmt.Errorf("bad url: %w, %s", err, h.URL)
	}
	if h.Method == "" {
		h.Method = defaultMethod
	}
	if h.Timeout <= 0 {
		h.Timeout = time.Second
	}
	return nil
}

func (h *HTTPHelper) Do(
	ctx context.Context, readBody bool, mapping func(string) string) ([]byte, error) {
	body := os.Expand(h.Body, mapping)
	url := os.Expand(h.URL, mapping)
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, h.Method, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request fail: url=%s %w", url, err)
	}
	for _, entry := range h.Headers {
		req.Header.Add(entry.Key, os.Expand(entry.Value, mapping))
	}
	if len(h.Args) > 0 {
		query := req.URL.Query()
		for _, entry := range h.Args {
			query.Add(entry.Key, os.Expand(entry.Value, mapping))
		}
		req.URL.RawQuery = query.Encode()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request fail: url=%s %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body := io.LimitReader(resp.Body, 1024)
		b, _ := io.ReadAll(body)
		return nil, fmt.Errorf("%s %s http status code %d, body=%s", req.Method, req.URL, resp.StatusCode, string(b))
	}
	if readBody {
		return io.ReadAll(resp.Body)
	}
	return nil, nil
}
