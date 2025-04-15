package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
)

func Start(cfg *Config, logger Logger) (stop, wait func(), err error) {
	var waits []func()
	ctx, cancel := context.WithCancel(context.Background())
	for _, v := range cfg.Discipline {
		var jails []*Jail
		for _, j := range v.Jail {
			idx := slices.IndexFunc(cfg.Jail, func(e *Jail) bool {
				return e.ID == j
			})
			if idx < 0 {
				return nil, nil, fmt.Errorf("jail id not exist: %s", v.Jail)
			}
			jails = append(jails, cfg.Jail[idx])
		}
		s, err := runDiscipline(ctx, cfg, v, jails, logger)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		waits = append(waits, s)
	}
	return cancel, func() {
		for _, w := range waits {
			w()
		}
	}, nil
}

func runDiscipline(ctx context.Context, cfg *Config, d *Discipline, js []*Jail, log Logger) (func(), error) {
	ch, err := d.Action.Watch(log)
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
					log.Errorf("close discipline fail: %v", err)
				}
				return
			case ip, ok := <-ch:
				if !ok {
					log.Debugf("[jail] watch channel close: %s", d.ID)
					return
				}
				if cfg.AllowIP(ip) ||
					ip.IsLoopback() || ip.IsUnspecified() ||
					ip.IsMulticast() {
					log.Debugf("[jail] ip is in allow list: %s", ip)
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
		log.Debugf("[jail][%s] start arrest %s", j.ID, ip)
		err := j.Action.Arrest(ip, log)
		if err != nil {
			log.Errorf("[jail][%s] arrest %s fail: %v", j.ID, ip, err)
		} else {
			log.Infof("[jail][%s] arrest %s success", j.ID, ip)
		}
	}

}
