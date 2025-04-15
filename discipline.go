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
	"time"

	"github.com/goccy/go-yaml"
	"github.com/hpcloud/tail"
)

func init() {
	RegisterDiscipline("log", NewFileDiscipline)
}

type FileDiscipline struct {
	Files   []string `yaml:"files"`
	Regexes []string `yaml:"regexes"`
	Counter Counter  `yaml:"counter"`
	regexes []*regexp.Regexp
	ctx     context.Context
	cancel  func()
	wg      sync.WaitGroup
	ipGroup int
}

var (
	regexReplacer = map[string]string{
		"%(ip)": `(?P<ip>(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))|(((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?))`,
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

func (fd *FileDiscipline) tail(f string) (t *tail.Tail, err error) {
	for range 3 {
		t, err = tail.TailFile(f, tail.Config{
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekEnd,
			},
			Follow:    true,
			ReOpen:    true,
			MustExist: true,
			Logger:    tail.DiscardingLogger,
		})
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
	var ch = make(chan net.IP, 1024)
	fd.addCancel(func() {
		close(ch)
	})
	for _, f := range fd.Files {
		t, err := fd.tail(f)
		if err != nil {
			close(ch)
			return nil, err
		}
		fd.wg.Add(1)
		go func(t *tail.Tail, f string) {
			defer fd.wg.Done()
			logger.Debugf("[discipline] watch file: %s", f)
			for {
				select {
				case <-fd.ctx.Done():
					t.Stop()
					t.Cleanup()
					return
				case line := <-t.Lines:
					if line.Err != nil {
						logger.Errorf("[discipline] tail file fail, retry %s: %v", f, line.Err)
						nt, err := fd.tail(f)
						if err != nil {
							logger.Errorf("[discipline] tail file fail: %v", err)
							fd.cancel()
							close(ch)
							return
						}
						t = nt
						continue
					}
					logger.Debugf("[discipline] get line from %s: length=%d", f, len(line.Text))
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
			logger.Debugf("[discipline] regex not match: %s: length=%d", f, len(line))
			return
		}
	}
	if len(groups) > fd.ipGroup {
		ip := groups[fd.ipGroup]
		if fd.Counter.Add(ip) {
			logger.Infof("[discipline] arrest: %s", ip)
			ch <- net.ParseIP(ip)
		} else {
			logger.Infof("[discipline] watch-on: %s", ip)
		}
	}
}
