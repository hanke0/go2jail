package main

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
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
