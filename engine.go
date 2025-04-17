package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
)

func Start(cfg *Config, logger Logger, test string, statListen string) (stop, wait func(), err error) {
	var cleaner Cleaner
	ctx, cancel := context.WithCancel(context.Background())
	if statListen != "" {
		server := http.Server{
			Addr: statListen,
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
		go func() {
			if err = server.ListenAndServe(); err != nil {
				logger.Errorf("http stats start fail: %v", err)
			}
		}()
		cleaner.Push(func() {
			server.Close()
		})
		old := cancel
		cancel = func() {
			old()
			server.Close()
		}
	}

	for _, v := range cfg.Discipline {
		var (
			jails     []*Jail
			testing   = test != ""
			jailNames = v.Jail
		)
		if testing {
			if v.ID != test {
				continue
			}
			jailNames = nil
			jails = []*Jail{testDisciplineJail}
		}
		for _, j := range jailNames {
			idx := slices.IndexFunc(cfg.Jail, func(e *Jail) bool {
				return e.ID == j
			})
			if idx < 0 {
				cancel()
				cleaner.Clean()
				return nil, nil, fmt.Errorf("jail id not exist: %s", v.Jail)
			}
			jails = append(jails, cfg.Jail[idx])
		}
		wait, err := runDiscipline(ctx, cfg, v, jails, logger, testing)
		if err != nil {
			cancel()
			cleaner.Clean()
			return nil, nil, err
		}
		cleaner.Push(wait)
	}
	if cleaner.Len() == 0 {
		cancel()
		cleaner.Clean()
		return nothing, nothing, nil
	}
	return cancel, cleaner.Clean, nil
}

func runDiscipline(ctx context.Context,
	cfg *Config, d *Discipline, js []*Jail,
	log Logger, test bool) (func(), error) {
	var (
		ch  <-chan net.IP
		err error
	)
	if test {
		ch, err = d.Action.Test(log)
	} else {
		ch, err = d.Action.Watch(log)
	}
	if err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				err := d.Action.Close()
				if err != nil {
					log.Errorf("[engine][discipline][%s] close discipline fail: %v", d.ID, err)
				}
				return
			case ip, ok := <-ch:
				if !ok {
					log.Debugf("[engine][discipline][%s] watch channel close", d.ID)
					return
				}
				if cfg.AllowIP(ip) ||
					ip.IsLoopback() || ip.IsUnspecified() ||
					ip.IsMulticast() {
					log.Debugf("[engine][discipline][%s] ip is in allow list: %s", d.ID, ip)
					continue
				}
				jailIp(js, ip, log)
			}
		}
	}()
	return wg.Wait, nil
}

func jailIp(js []*Jail, ip net.IP, log Logger) {
	for _, j := range js {
		log.Debugf("[engine][jail][%s] start arrest %s", j.ID, ip)
		err := j.Action.Arrest(ip, log)
		if err != nil {
			log.Errorf("[engine][jail][%s] arrest %s fail: %v", j.ID, ip, err)
			CountArrestFail.Incr()
		} else {
			log.Infof("[engine][jail][%s] arrest %s success", j.ID, ip)
			CountArrestSuccess.Incr()
		}
	}
}

var (
	CountArrestSuccess = RegisterNewCounter("total_arrest_success")
	CountArrestFail    = RegisterNewCounter("total_arrest_fail")
)
