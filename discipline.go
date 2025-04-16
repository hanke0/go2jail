package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/hpcloud/tail"
)

func init() {
	RegisterDiscipline("log", NewFileDiscipline)
}

type FileDiscipline struct {
	ID      string   `yaml:"id"`
	Files   []string `yaml:"files"`
	Regexes []string `yaml:"regexes"`
	Counter Counter  `yaml:"counter"`
	regexes []*regexp.Regexp
	ctx     context.Context
	cancel  func()
	wg      sync.WaitGroup
	wgCount atomic.Int32

	ipGroup int
}

var (
	regexReplacer = map[string]string{
		"%(ip)": `(?P<ip>(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})|([0-9]{1,3}(\.[0-9]{1,3}){3}))`,
	}
)

func replaceRegex(r string) string {
	for k, v := range regexReplacer {
		r = strings.ReplaceAll(r, k, v)
	}
	return r
}

func NewFileDiscipline(b []byte) (Discipliner, error) {
	var f FileDiscipline
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for _, r := range f.Regexes {
		r = replaceRegex(r)
		p, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("bad regex: %w", err)
		}
		f.regexes = append(f.regexes, p)
	}
	if len(f.regexes) == 0 {
		return nil, errors.New("regexes not setting")
	}
	last := f.regexes[len(f.regexes)-1]
	for i, name := range last.SubexpNames() {
		switch name {
		case "ip":
			if f.ipGroup > 0 {
				return nil, fmt.Errorf("too many regex group: %s", last.String())
			}
			f.ipGroup = i
		}
	}
	if f.ipGroup <= 0 {
		return nil, fmt.Errorf("last regex do not contains ip group: %s", last.String())
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	return &f, nil
}

func (fd *FileDiscipline) tail(f string, testing bool) (t *tail.Tail, err error) {
	cfg := tail.Config{
		Location: &tail.SeekInfo{
			Offset: 0,
			Whence: io.SeekEnd,
		},
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
		Logger:    tail.DiscardingLogger,
	}
	if testing {
		cfg.Location = nil
		cfg.Follow = false
		cfg.ReOpen = false
	}
	for range 3 {
		t, err = tail.TailFile(f, cfg)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	return
}

func (fd *FileDiscipline) addCancel(f func()) {
	old := fd.cancel
	fd.cancel = func() {
		old()
		f()
	}
}

func (fd *FileDiscipline) Watch(logger Logger) (<-chan net.IP, error) {
	return fd.watch(logger, false)
}

func (fd *FileDiscipline) Test(logger Logger) (<-chan net.IP, error) {
	return fd.watch(logger, true)
}

func (fd *FileDiscipline) watch(logger Logger, testing bool) (<-chan net.IP, error) {
	var ch = make(chan net.IP, 1024)
	var once sync.Once
	fd.addCancel(func() {
		once.Do(func() {
			close(ch)
		})
	})
	for _, f := range fd.Files {
		t, err := fd.tail(f, testing)
		if err != nil {
			close(ch)
			return nil, err
		}
		fd.wg.Add(1)
		fd.wgCount.Add(1)
		go func(t *tail.Tail, f string) {
			defer func() {
				fd.wg.Done()
				if fd.wgCount.Add(-1) <= 0 {
					fd.cancel()
				}
			}()
			logger.Debugf("[discipline][%s] watch file: %s", fd.ID, f)
			for {
				select {
				case <-fd.ctx.Done():
					logger.Infof("[discipline][%s] file closed: %s", fd.ID, f)
					t.Stop()
					t.Cleanup()
					return
				case line, ok := <-t.Lines:
					if !ok {
						logger.Infof("[discipline][%s] file closed: %s", fd.ID, f)
						t.Stop()
						t.Cleanup()
						return
					}
					if line.Err != nil {
						logger.Errorf("[discipline][%s] tail file fail %s: %v", fd.ID, f, line.Err)
						t.Stop()
						t.Cleanup()
						fd.cancel()
						return
					}
					logger.Debugf("[discipline][%s] get line from %s: length=%d", fd.ID, f, len(line.Text))
					if len(line.Text) > 0 {
						fd.doLine(f, line.Text, ch, logger)
					}
				}
			}
		}(t, f)
	}
	return ch, nil
}

func (fd *FileDiscipline) Close() error {
	fd.cancel()
	fd.wg.Wait()
	fd.Counter.Stop()
	return nil
}

func (fd *FileDiscipline) doLine(f, line string, ch chan<- net.IP, logger Logger) {
	var groups []string
	for _, re := range fd.regexes {
		groups = re.FindStringSubmatch(line)
		if len(groups) > 0 {
			line = groups[0]
		} else {
			logger.Debugf("[discipline][%s] regex not match: %s: length=%d", fd.ID, f, len(line))
			return
		}
	}
	if len(groups) > fd.ipGroup {
		ip := net.ParseIP(groups[fd.ipGroup])
		if ip == nil {
			return
		}
		sip := ip.String()
		if fd.Counter.Add(sip) {
			logger.Errorf("[discipline][%s] arrest: %s", fd.ID, sip)
			ch <- ip
		} else {
			logger.Infof("[discipline][%s] watch-on: %s", fd.ID, sip)
		}
	}
}
