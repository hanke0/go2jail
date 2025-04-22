package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hpcloud/tail"
)

func init() {
	RegisterWatcher("file", NewFileWatch)
	RegisterWatcher("shell", NewShellWatch)
}

type FileWatch struct {
	BaseWatch             `yaml:",inline"`
	Files                 []string `yaml:"files"`
	SkipWhenFileNotExists bool     `yaml:"skip_when_file_not_exists"`

	ctx     context.Context
	cancel  Finisher
	wg      sync.WaitGroup
	wgCount atomic.Int32
}

func NewFileWatch(decode Decoder) (Watcher, error) {
	var f FileWatch
	if err := decode(&f); err != nil {
		return nil, err
	}
	if len(f.Files) == 0 {
		return nil, fmt.Errorf("[watch-%s] files is empty", f.ID)
	}
	var cancel func()
	f.ctx, cancel = context.WithCancel(context.Background())
	f.cancel.Push(cancel)
	return &f, nil
}

func (fd *FileWatch) tail(f string, testing bool) (t *tail.Tail, err error) {
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

func (fd *FileWatch) Watch(logger Logger) (<-chan Line, error) {
	return fd.watch(logger, false)
}

func (fd *FileWatch) Test(logger Logger) (<-chan Line, error) {
	return fd.watch(logger, true)
}

func (fd *FileWatch) watch(logger Logger, testing bool) (<-chan Line, error) {
	logger.Debugf("[watch-%s] watch starting", fd.ID)
	ch := NewChan[Line](0)
	fd.cancel.Push(ch.Close)
	for _, f := range fd.Files {
		if fd.SkipWhenFileNotExists {
			_, err := os.Open(f)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		t, err := fd.tail(f, testing)
		if err != nil {
			fd.cancel.Finish()
			return nil, err
		}
		fd.wg.Add(1)
		fd.wgCount.Add(1)
		go func(t *tail.Tail, f string) {
			defer func() {
				fd.wg.Done()
				// all files closed read. stop watch
				if fd.wgCount.Add(-1) <= 0 {
					fd.cancel.Finish()
				}
				t.Stop()
				t.Cleanup()
			}()
			logger.Debugf("[watch-%s] watch file: %s", fd.ID, f)
			for {
				select {
				case <-fd.ctx.Done():
					logger.Infof("[watch-%s] file closed: %s", fd.ID, f)
					return
				case line, ok := <-t.Lines:
					if !ok {
						logger.Infof("[watch-%s] file closed: %s", fd.ID, f)
						return
					}
					if line.Err != nil {
						logger.Errorf("[watch-%s] tail file fail %s: %v", fd.ID, f, line.Err)
						return
					}
					logger.Debugf("[watch-%s] get line from %s: length=%d", fd.ID, f, len(line.Text))
					l := NewLine(fd.ID, line.Text)
					if err := ch.Send(l); err != nil {
						return
					}
				}
			}
		}(t, f)
	}
	return ch.Reader(), nil
}

func (fd *FileWatch) Close() error {
	fd.cancel.Finish()
	fd.wg.Wait()
	return nil
}

type ShellWatch struct {
	BaseWatch     `yaml:",inline"`
	Run           string `yaml:"run"`
	ScriptOption  `yaml:",inline"`
	RestartPolicy *RestartPolicy `yaml:"restart_policy"`

	ch     *Chan[string]
	wg     sync.WaitGroup
	ctx    context.Context
	cancel func()
}

func NewShellWatch(decode Decoder) (Watcher, error) {
	var s ShellWatch
	if err := decode(&s); err != nil {
		return nil, err
	}
	if s.RestartPolicy == nil {
		return nil, fmt.Errorf("[watch-%s] restart_policy is nil", s.ID)
	}
	if err := s.ScriptOption.SetupShell(); err != nil {
		return nil, fmt.Errorf("[watch-%s] setup shell fail: %w", s.ID, err)
	}
	s.ch = NewChan[string](0)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return &s, nil
}

func (sd *ShellWatch) Test(logger Logger) (<-chan Line, error) {
	v, err := sd.Watch(logger)
	sd.RestartPolicy.Stop()
	return v, err
}

func (sd *ShellWatch) Watch(logger Logger) (<-chan Line, error) {
	logger.Infof("[watch-%s] watch starting", sd.ID)
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
			logger.Debugf("[watch-%s] waiting exec exit", sd.ID)
			err := cmd.Wait()
			cancel()
			logger.Debugf("[watch-%s] exec exit with error: %v", sd.ID, err)
			return err
		}
		exeErr := waitExit()
		for sd.RestartPolicy.Next(exeErr) {
			logger.Debugf("[watch-%s] exec restart: exiterr=%v", sd.ID, exeErr)
			cmd, cancel, exeErr = sd.execute(logger)
			if exeErr == nil {
				exeErr = waitExit()
			}
			select {
			case <-sd.ctx.Done():
				logger.Infof("[watch-%s] exec exit by context done", sd.ID)
				return
			default:
			}
		}
		logger.Infof("[watch-%s] exec exit by restart_policy: exiterr=%v", sd.ID, exeErr)
	}()
	ch := NewChan[Line](0)
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
				logger.Infof("[watch-%s] close watch context done", sd.ID)
				return
			case line, ok := <-rd:
				if !ok {
					logger.Infof("[watch-%s] close watch channel closed", sd.ID)
					return
				}
				l := NewLine(sd.ID, line)
				if err := ch.Send(l); err != nil {
					logger.Infof("[watch-%s] send line to channel fail: %v", sd.ID, err)
					return
				}
			}
		}
	}()
	logger.Infof("[watch-%s] watch started", sd.ID)
	return ch.Reader(), nil
}

func (sd *ShellWatch) execute(logger Logger) (cmd *exec.Cmd, cancel func(), err error) {
	opt := &ScriptOption{
		Shell:        sd.ScriptOption.Shell,
		ShellOptions: sd.ScriptOption.ShellOptions,
		Timeout:      -1,
		Stdout:       ChanWriter(sd.ch),
		Stderr:       ChanWriter(sd.ch),
	}
	cmd, cancelCtx, err := NewScript(sd.Run, opt, sd.ID)
	if err != nil {
		logger.Errorf("[watch-%s] new shell script fail: %v", sd.ID, err)
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancelCtx()
		logger.Errorf("[watch-%s] start shell script fail: %v", sd.ID, err)
		return nil, nil, err
	}
	return cmd, func() {
		cancelCtx()
		cmd.Stdout.(io.Closer).Close()
		cmd.Stderr.(io.Closer).Close()
	}, nil
}

func (sd *ShellWatch) clean() {
	sd.cancel()
	sd.ch.Close()
}

func (sd *ShellWatch) Close() error {
	sd.clean()
	sd.wg.Wait()
	return nil
}
