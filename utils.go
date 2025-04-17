package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os/exec"
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

type ExecuteOptions struct {
	Timeout    time.Duration `yaml:"timeout"`
	OutputSize int           `yaml:"output_size"`
	Program    []string      `yaml:"program"`
}

func Execute(opt ExecuteOptions) (string, error) {
	if len(opt.Program) == 0 {
		return "", errors.New("execute must provides at least 1 program value")
	}
	var t = opt.Timeout
	if t == 0 {
		t = time.Second * 60
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	cmd := exec.CommandContext(ctx, opt.Program[0], opt.Program[1:]...)
	var buf *RingBuffer
	if opt.OutputSize > 0 {
		buf = NewRingBuffer(opt.OutputSize)
		cmd.Stdout = buf
		cmd.Stderr = cmd.Stdout
	}
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	if err != nil {
		if buf != nil {
			return string(buf.Bytes()), fmt.Errorf("%w: args=%v", err, opt.Program)
		}
		return "", fmt.Errorf("%w: args=%v", err, opt.Program)
	}
	if buf == nil {
		return "", nil
	}
	return string(buf.Bytes()), nil
}

type counterStats struct {
	n          int
	expiration time.Time
}

type Limiter struct {
	max     int
	timeout time.Duration
	sync.Once
	mu     sync.Mutex
	wg     sync.WaitGroup
	ctx    context.Context
	cancel func()
	mp     map[string]*counterStats
}

func (c *Limiter) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return err
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return fmt.Errorf("bad counter: %s", s)
	}
	max, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf("bad counter: %s", s)
	}
	d := strings.TrimSpace(parts[1])
	if !strings.ContainsAny(d, "0123456789") {
		d = "1" + d
	}
	timeout, err := time.ParseDuration(d)
	if err != nil {
		return fmt.Errorf("bad counter: %s", s)
	}
	c.max = max
	c.timeout = timeout
	return nil
}

func (c *Limiter) startBackground() {
	c.wg.Add(1)
	c.ctx, c.cancel = context.WithCancel(context.Background())
	go func() {
		tick := time.NewTicker(c.timeout)
		for {
			select {
			case <-c.ctx.Done():
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

func (c *Limiter) Add(s string) bool {
	if c.timeout == 0 {
		c.timeout = time.Second
	}
	c.Once.Do(c.startBackground)
	c.mu.Lock()
	defer c.mu.Unlock()
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
	return v.n >= c.max
}

func (c *Limiter) Stop() {
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
