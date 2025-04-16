package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
	if err := cmd.Start(); err != nil {
		if buf != nil {
			return string(buf.Bytes()), err
		}
		return "", err
	}
	err := cmd.Wait()
	if buf != nil {
		return string(buf.Bytes()), err
	}
	return "", err
}

type counterStats struct {
	n          int
	expiration time.Time
}

type Counter struct {
	max     int
	timeout time.Duration
	sync.Once
	mu     sync.Mutex
	wg     sync.WaitGroup
	ctx    context.Context
	cancel func()
	mp     map[string]*counterStats
}

func (c *Counter) UnmarshalYAML(b []byte) error {
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
	timeout, err := time.ParseDuration(strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf("bad counter: %s", s)
	}
	c.max = max
	c.timeout = timeout
	return nil
}

func (c *Counter) startBackground() {
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

func (c *Counter) Add(s string) bool {
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

func (c *Counter) Stop() {
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

func (c *Chan[T]) Send(v T) (ok bool) {
	if c.closed {
		return false
	}
	defer func() {
		recover()
		ok = false
	}()
	c.ch <- v
	return true
}

func (c *Chan[T]) Reader() <-chan T {
	return c.ch
}
