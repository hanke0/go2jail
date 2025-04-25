package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
)

type watchCallback struct {
	d  *Discipline
	js []*Jail
}

func (w watchCallback) Exec(line Line, allow Allows, logger Logger) {
	bad, ok := w.d.Action.Judge(line, allow, logger)
	if !ok {
		return
	}
	ip := bad.IP
	logger.Debugf("[engine][discipline-%s][watch-%s] bad ip: %s %s", bad.DisciplineID, bad.WatchID, ip, bad.Line)
	for _, j := range w.js {
		if j.Background {
			go runJail(bad, j, logger)
		} else {
			runJail(bad, j, logger)
		}
	}
}

func runJail(bad BadLog, j *Jail, logger Logger) {
	ip := bad.IP
	logger.Debugf("[engine][discipline-%s][watch-%s][jail-%s] start arrest %s by line: %s", bad.DisciplineID, bad.WatchID, j.ID, ip, bad.Line)
	err := j.Action.Arrest(bad, logger)
	if err != nil {
		logger.Errorf("[engine][discipline-%s][watch-%s][jail-%s] arrest %s by line: %s fail: %v", bad.DisciplineID, bad.WatchID, j.ID, ip, bad.Line, err)
		CountArrestFail.Incr()
	} else {
		logger.Infof("[engine][discipline-%s][watch-%s][jail-%s] arrest success: %s", bad.DisciplineID, bad.WatchID, j.ID, ip)
		CountArrestSuccess.Incr()
	}
}

type Engine struct {
	watchList map[*Watch][]watchCallback
	cancels   Finisher
	waits     Finisher
	ctx       context.Context
	logger    Logger
}

func newEngine(logger Logger) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		watchList: make(map[*Watch][]watchCallback),
		ctx:       ctx,
		logger:    logger,
	}
	e.cancels.Push(cancel)
	return e
}

func (e *Engine) Wait() {
	e.logger.Debugf("wait cleanup")
	e.waits.Finish()
}

func (e *Engine) Stop() {
	e.cancels.Finish()
	e.logger.Infof("stop toggled")
}

func (e *Engine) StopAndWait() {
	e.Stop()
	e.Wait()
}

func (e *Engine) AddDiscipline(w *Watch, d *Discipline, js []*Jail) {
	e.watchList[w] = append(e.watchList[w], watchCallback{d: d, js: js})
	e.cancels.Push(func() {
		d.Action.Close()
	})
}

func (e *Engine) StartStatServer(addr string, logger Logger) {
	server := http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			OutputCounters(w)
		}),
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Errorf("http stats start fail: %v", err)
		}
	}()
	e.cancels.Push(func() {
		server.Close()
	})
	e.waits.Prepend(wg.Wait)
}

func (e *Engine) Start(testing bool, allow Allows, logger Logger) error {
	if len(e.watchList) == 0 {
		return fmt.Errorf("nothing to do")
	}
	for w, callbacks := range e.watchList {
		if err := e.startWatch(testing, w, callbacks, allow, logger); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) startWatch(testing bool,
	w *Watch, callbacks []watchCallback, allow Allows, log Logger) error {
	var (
		ch  <-chan Line
		err error
	)
	if testing {
		ch, err = w.Action.Test(log)
	} else {
		ch, err = w.Action.Watch(log)
	}
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-e.ctx.Done():
				err := w.Action.Close()
				if err != nil {
					log.Errorf("[engine][watch-%s] close watch fail: %v", w.ID, err)
				}
				return
			case line, ok := <-ch:
				if !ok {
					log.Debugf("[engine][discipline-%s] watch channel close", w.ID)
					return
				}
				for _, c := range callbacks {
					c.Exec(line, allow, log)
				}
			}
		}
	}()
	e.waits.Push(wg.Wait)
	return nil
}

func Start(cfg *Config, logger Logger, test string, statListen string) (wait, stop func(), err error) {
	logger.Debugf("starting with config: \n%s", cfg)
	eg := newEngine(logger)
	if statListen != "" {
		eg.StartStatServer(statListen, logger)
	}
	testing := test != ""
	for _, d := range cfg.Disciplines {
		var (
			jails     []*Jail
			jailNames = d.Jails
		)
		if testing {
			if d.ID != test {
				continue
			}
			jailNames = nil
			jails = []*Jail{testDisciplineJail}
		}
		for _, j := range jailNames {
			idx := slices.IndexFunc(cfg.Jails, func(e *Jail) bool {
				return e.ID == j
			})
			if idx < 0 {
				eg.StopAndWait()
				return nil, nil, fmt.Errorf("jail id not exist: %s", j)
			}
			jails = append(jails, cfg.Jails[idx])
		}
		for _, w := range d.Watches {
			idx := slices.IndexFunc(cfg.Watches, func(e *Watch) bool {
				return e.ID == w
			})
			if idx < 0 {
				eg.StopAndWait()
				return nil, nil, fmt.Errorf("watch id not exist: %s", w)
			}
			eg.AddDiscipline(cfg.Watches[idx], d, jails)
		}
	}
	if err := eg.Start(testing, cfg.Allows, logger); err != nil {
		eg.StopAndWait()
		return nil, nil, err
	}
	return eg.Wait, eg.Stop, nil
}

var (
	CountArrestSuccess = RegisterNewCounter("total_arrest_success")
	CountArrestFail    = RegisterNewCounter("total_arrest_fail")
)
