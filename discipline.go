package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/hpcloud/tail"
)

func init() {
	RegisterDiscipline("log", NewFileDiscipline)
}

type disciplineCounter struct {
	tailLinesCount       *Counter
	matchLineCount       *Counter
	badIPLineCount       *Counter
	watchIPCount         *Counter
	sendJailSuccessCount *Counter
	sendJailFailCount    *Counter
}

func (f *disciplineCounter) initCounter(id string) {
	f.tailLinesCount = RegisterNewCounter(fmt.Sprintf("%s_tail_lines", id))
	f.matchLineCount = RegisterNewCounter(fmt.Sprintf("%s_match_lines", id))
	f.badIPLineCount = RegisterNewCounter(fmt.Sprintf("%s_bad_ip_lines", id))
	f.watchIPCount = RegisterNewCounter(fmt.Sprintf("%s_watch_ip", id))
	f.sendJailSuccessCount = RegisterNewCounter(fmt.Sprintf("%s_send_jail_success", id))
	f.sendJailFailCount = RegisterNewCounter(fmt.Sprintf("%s_send_jail_fail", id))
}

type FileDiscipline struct {
	ID                    string   `yaml:"id"`
	Files                 []string `yaml:"files"`
	Matches               *Matcher `yaml:"matches,omitempty"`
	Ignores               *Matcher `yaml:"ignores,omitempty"`
	Rate                  *Limiter `yaml:"rate,omitempty"`
	SkipWhenFileNotExists bool     `yaml:"skip_when_file_not_exists"`

	disciplineCounter
	ctx     context.Context
	cancel  func()
	wg      sync.WaitGroup
	wgCount atomic.Int32
}

func NewFileDiscipline(b []byte) (Discipliner, error) {
	var f FileDiscipline
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Matches == nil {
		return nil, fmt.Errorf("[discipline][%s] matches is nil", f.ID)
	}
	if err := f.Matches.ExpectGroups("ip"); err != nil {
		return nil, fmt.Errorf("[discipline][%s] matches: %w", f.ID, err)
	}

	f.ctx, f.cancel = context.WithCancel(context.Background())
	if f.ID == "" {
		f.ID = randomString(8)
	}
	f.disciplineCounter.initCounter(f.ID)
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
	logger.Infof("[discipline][%s] watch start: rate=%s", fd.ID, fd.Rate.String())
	ch := NewChan[net.IP](0)
	fd.addCancel(ch.Close)
	for _, f := range fd.Files {
		if fd.SkipWhenFileNotExists {
			_, err := os.Open(f)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		t, err := fd.tail(f, testing)
		if err != nil {
			fd.cancel()
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
				t.Stop()
				t.Cleanup()
			}()
			logger.Debugf("[discipline][%s] watch file: %s", fd.ID, f)
			for {
				select {
				case <-fd.ctx.Done():
					logger.Infof("[discipline][%s] file closed: %s", fd.ID, f)
					return
				case line, ok := <-t.Lines:
					if !ok {
						logger.Infof("[discipline][%s] file closed: %s", fd.ID, f)
						return
					}
					if line.Err != nil {
						logger.Errorf("[discipline][%s] tail file fail %s: %v", fd.ID, f, line.Err)
						return
					}
					logger.Debugf("[discipline][%s] get line from %s: length=%d", fd.ID, f, len(line.Text))
					fd.tailLinesCount.Incr()
					if len(line.Text) > 0 {
						if err := fd.doLine(f, line.Text, ch, logger); err != nil {
							return
						}
					}
				}
			}
		}(t, f)
	}
	if fd.wgCount.Load() == 0 {
		fd.cancel()
		return ch.Reader(), nil
	}
	return ch.Reader(), nil
}

func (fd *FileDiscipline) Close() error {
	fd.cancel()
	fd.wg.Wait()
	fd.Rate.Stop()
	return nil
}

func (fd *FileDiscipline) doLine(f, line string, ch *Chan[net.IP], logger Logger) error {
	groups := fd.Matches.Match(line)
	if len(groups) == 0 {
		logger.Debugf("[discipline][%s] regex not match: %s: length=%d", fd.ID, f, len(line))
		return nil
	}
	if fd.Ignores != nil && fd.Ignores.Test(groups[0]) {
		logger.Debugf("[discipline][%s] regex ignore: %s: length=%d", fd.ID, f, len(line))
		return nil
	}
	fd.matchLineCount.Incr()
	ip := net.ParseIP(groups[1])
	if ip == nil {
		fd.badIPLineCount.Incr()
		return nil
	}
	sip := ip.String()
	if desc, ok := fd.Rate.Add(sip); ok {
		if err := ch.Send(ip); err != nil {
			logger.Errorf("[discipline][%s] arrest send fail: %s %v", fd.ID, sip, err)
			fd.sendJailFailCount.Incr()
			return err
		}
		fd.sendJailSuccessCount.Incr()
		logger.Infof("[discipline][%s] arrest(%s): %s", fd.ID, desc, sip)
	} else {
		fd.watchIPCount.Incr()
		logger.Infof("[discipline][%s] watch-on(%s): %s", fd.ID, desc, sip)
	}
	return nil
}
