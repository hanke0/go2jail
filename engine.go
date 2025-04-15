package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
)

func Start(cfg *Config, logger Logger) (stop func(), err error) {
	var stops []func()
	ctx, cancel := context.WithCancel(context.Background())
	stopAll := func() {
		cancel()
		for _, s := range stops {
			s()
		}
		for _, v := range cfg.Jail {
			v.Action.Close()
		}
	}
	for _, v := range cfg.Discipline {
		idx := slices.IndexFunc(cfg.Jail, func(e *Jail) bool {
			return e.ID == v.Jail
		})
		if idx < 0 {
			return nil, fmt.Errorf("jail id not exist: %s", v.Jail)
		}
		s, err := runDiscipline(ctx, cfg, v, cfg.Jail[idx], logger)
		if err != nil {
			stopAll()
			return nil, err
		}
		stops = append(stops, s)
	}
	return stopAll, nil
}

func runDiscipline(ctx context.Context, cfg *Config, d *Discipline, j *Jail, log Logger) (func(), error) {
	ch := make(chan net.IP, 32)
	d.Action.Watch(ch, log)
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
			case ip := <-ch:
				if cfg.AllowIP(ip) {
					continue
				}
				jailIp(j, ip, log)
			}
		}
	}()
	return wg.Wait, nil
}

func jailIp(j *Jail, ip net.IP, log Logger) {
	if ip.IsLoopback() || ip.IsGlobalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return
	}
	err := j.Action.Arrest(ip, log)
	if err != nil {
		log.Errorf("[jail][%s] arrest %s fail: %v", j.ID, ip, err)
	} else {
		log.Infof("[jail][%s] arrest %s success", j.ID, ip)
	}
}
