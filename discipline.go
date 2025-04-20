package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/hpcloud/tail"
)

func init() {
	RegisterDiscipline("log", NewFileDiscipline)
	RegisterDiscipline("shell", NewShellDiscipline)
}

type CommonDiscipline struct {
	Matches *Matcher `yaml:"matches,omitempty"`
	Ignores *Matcher `yaml:"ignores,omitempty"`
	Rate    *Limiter `yaml:"rate,omitempty"`

	tailLinesCount       *Counter
	matchLineCount       *Counter
	badIPLineCount       *Counter
	watchIPCount         *Counter
	sendJailSuccessCount *Counter
	sendJailFailCount    *Counter
}

func (f *CommonDiscipline) Init(id string) error {
	f.tailLinesCount = RegisterNewCounter(fmt.Sprintf("%s_tail_lines", id))
	f.matchLineCount = RegisterNewCounter(fmt.Sprintf("%s_match_lines", id))
	f.badIPLineCount = RegisterNewCounter(fmt.Sprintf("%s_bad_ip_lines", id))
	f.watchIPCount = RegisterNewCounter(fmt.Sprintf("%s_watch_ip", id))
	f.sendJailSuccessCount = RegisterNewCounter(fmt.Sprintf("%s_send_jail_success", id))
	f.sendJailFailCount = RegisterNewCounter(fmt.Sprintf("%s_send_jail_fail", id))
	if f.Matches == nil {
		return fmt.Errorf("[discipline][%s] matches is nil", id)
	}
	if err := f.Matches.ExpectGroups("ip"); err != nil {
		v, _ := f.Matches.MarshalYAML()
		return fmt.Errorf("[discipline][%s] bad matches: %w, %s", id, err, v)
	}
	return nil
}

func (fd *CommonDiscipline) doLine(prefix, line string, ch *Chan[BadLog], logger Logger) error {
	fd.tailLinesCount.Incr()
	if line == "" || fd.Matches == nil {
		return nil
	}
	fd.tailLinesCount.Incr()
	groups := fd.Matches.Match(line)
	if len(groups) == 0 {
		logger.Debugf("[discipline][%s] regex not match: %s: length=%d", prefix, len(line))
		return nil
	}
	if fd.Ignores != nil && fd.Ignores.Test(groups[0]) {
		logger.Debugf("[discipline][%s] regex ignore: %s: length=%d", prefix, len(line))
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
		if err := ch.Send(BadLog{
			IP:   ip,
			Line: line,
		}); err != nil {
			logger.Errorf("[discipline][%s] arrest send fail: %s %v", prefix, sip, err)
			fd.sendJailFailCount.Incr()
			return err
		}
		fd.sendJailSuccessCount.Incr()
		logger.Infof("[discipline][%s] arrest(%s): %s %s", prefix, desc, sip, line)
	} else {
		fd.watchIPCount.Incr()
		logger.Infof("[discipline][%s] watch-on(%s): %s %s", prefix, desc, sip, line)
	}
	return nil
}

type FileDiscipline struct {
	ID               string   `yaml:"id"`
	Files            []string `yaml:"files"`
	CommonDiscipline `yaml:",inline"`

	SkipWhenFileNotExists bool `yaml:"skip_when_file_not_exists"`

	ctx     context.Context
	cancel  Cleaner
	wg      sync.WaitGroup
	wgCount atomic.Int32
}

func NewFileDiscipline(b []byte) (Discipliner, error) {
	var f FileDiscipline
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.ID == "" {
		f.ID = randomString(8)
	}
	if len(f.Files) == 0 {
		return nil, fmt.Errorf("[discipline][%s] files is empty", f.ID)
	}
	if err := f.CommonDiscipline.Init(f.ID); err != nil {
		return nil, err
	}
	var cancel func()
	f.ctx, cancel = context.WithCancel(context.Background())
	f.cancel.Prepend(cancel)
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

func (fd *FileDiscipline) Watch(logger Logger) (<-chan BadLog, error) {
	return fd.watch(logger, false)
}

func (fd *FileDiscipline) Test(logger Logger) (<-chan BadLog, error) {
	return fd.watch(logger, true)
}

func (fd *FileDiscipline) watch(logger Logger, testing bool) (<-chan BadLog, error) {
	logger.Infof("[discipline][%s] watch start: rate=%s", fd.ID, fd.Rate.String())
	ch := NewChan[BadLog](0)
	fd.cancel.Prepend(ch.Close)
	for _, f := range fd.Files {
		if fd.SkipWhenFileNotExists {
			_, err := os.Open(f)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		t, err := fd.tail(f, testing)
		if err != nil {
			fd.cancel.Clean()
			return nil, err
		}
		fd.wg.Add(1)
		fd.wgCount.Add(1)
		go func(t *tail.Tail, f string) {
			defer func() {
				fd.wg.Done()
				// all files closed read. stop watch
				if fd.wgCount.Add(-1) <= 0 {
					fd.cancel.Clean()
				}
				t.Stop()
				t.Cleanup()
			}()
			logger.Debugf("[discipline][%s] watch file: %s", fd.ID, f)
			prefix := fd.ID + f
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
					if err := fd.CommonDiscipline.doLine(prefix, line.Text, ch, logger); err != nil {
						return
					}
				}
			}
		}(t, f)
	}
	return ch.Reader(), nil
}

func (fd *FileDiscipline) Close() error {
	fd.cancel.Clean()
	fd.wg.Wait()
	fd.Rate.Stop()
	return nil
}

type ShellDiscipline struct {
	ID               string `yaml:"id"`
	Run              string `yaml:"run"`
	ScriptOption     `yaml:",inline"`
	CommonDiscipline `yaml:",inline"`
	RestartPolicy    *RestartPolicy `yaml:"restart_policy"`

	ch     *Chan[string]
	wg     sync.WaitGroup
	ctx    context.Context
	cancel func()
}

func NewShellDiscipline(b []byte) (Discipliner, error) {
	var s ShellDiscipline
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if err := s.CommonDiscipline.Init(s.ID); err != nil {
		return nil, err
	}
	if s.RestartPolicy == nil {
		return nil, fmt.Errorf("[discipline][%s] restart_policy is nil", s.ID)
	}
	if err := s.ScriptOption.SetupShell(); err != nil {
		return nil, fmt.Errorf("[discipline][%s] setup shell fail: %w", s.ID, err)
	}
	s.ch = NewChan[string](0)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return &s, nil
}

func (sd *ShellDiscipline) Test(logger Logger) (<-chan BadLog, error) {
	v, err := sd.Watch(logger)
	sd.RestartPolicy.Stop()
	return v, err
}

func (sd *ShellDiscipline) Watch(logger Logger) (<-chan BadLog, error) {
	logger.Infof("[discipline][%s] watch starting", sd.ID)
	sd.RestartPolicy.Next(nil)
	cmd, cancel, err := sd.execute(logger)
	if err != nil {
		sd.clean()
		return nil, err
	}
	sd.wg.Add(1)
	go func() {
		defer func() {
			sd.clean()
			sd.wg.Done()
		}()
		waitExit := func() error {
			logger.Debugf("[discipline][%s] waiting exec exit", sd.ID)
			err := cmd.Wait()
			cancel()
			logger.Debugf("[discipline][%s] exec exit with error: %v", sd.ID, err)
			return err
		}
		exeErr := waitExit()
		for sd.RestartPolicy.Next(exeErr) {
			logger.Debugf("[discipline][%s] exec restart: exiterr=%v", sd.ID, exeErr)
			cmd, cancel, exeErr = sd.execute(logger)
			if exeErr == nil {
				exeErr = waitExit()
			}
			select {
			case <-sd.ctx.Done():
				logger.Infof("[discipline][%s] exec exit by context done", sd.ID)
				return
			default:
			}
		}
		logger.Infof("[discipline][%s] exec exit by restart_policy: exiterr=%v", sd.ID, exeErr)
	}()
	ch := NewChan[BadLog](0)
	sd.wg.Add(1)
	go func() {
		defer func() {
			sd.clean()
			sd.wg.Done()
		}()
		rd := sd.ch.Reader()
		for {
			select {
			case <-sd.ctx.Done():
				logger.Infof("[discipline][%s] close watch context done", sd.ID)
				return
			case line, ok := <-rd:
				if !ok {
					logger.Infof("[discipline][%s] close watch channel closed", sd.ID)
					return
				}
				if err := sd.CommonDiscipline.doLine(sd.ID, line, ch, logger); err != nil {
					logger.Infof("[discipline][%s] closed with fail", sd.ID, err)
					return
				}
			}
		}
	}()
	logger.Infof("[discipline][%s] watch started", sd.ID)
	return ch.Reader(), nil
}

func (sd *ShellDiscipline) execute(logger Logger) (cmd *exec.Cmd, cancel func(), err error) {
	opt := &ScriptOption{
		Shell:        sd.ScriptOption.Shell,
		ShellOptions: sd.ScriptOption.ShellOptions,
		Timeout:      -1,
		Stdout:       ChanWriter(sd.ch),
		Stderr:       ChanWriter(sd.ch),
	}
	cmd, cancelCtx, err := NewScript(sd.Run, opt, sd.ID)
	if err != nil {
		logger.Errorf("[discipline][%s] new shell script fail: %v", sd.ID, err)
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancelCtx()
		logger.Errorf("[discipline][%s] start shell script fail: %v", sd.ID, err)
		return nil, nil, err
	}
	return cmd, func() {
		cancelCtx()
		cmd.Stdout.(io.Closer).Close()
		cmd.Stderr.(io.Closer).Close()
	}, nil
}

func (sd *ShellDiscipline) clean() {
	sd.cancel()
	sd.ch.Close()
}

func (sd *ShellDiscipline) Close() error {
	sd.clean()
	sd.wg.Wait()
	return nil
}
