package main

import (
	"fmt"
	"net"
)

func init() {
	RegisterDiscipliner("regex", NewRegexDiscipline)
}

type RegexDiscipline struct {
	BaseDiscipline `yaml:",inline"`
	Matches        *Matcher `yaml:"matches,omitempty"`
	Ignores        *Matcher `yaml:"ignores,omitempty"`
	Rate           *Limiter `yaml:"rate,omitempty"`
	Allows         Allows   `yaml:"allows"`

	tailLinesCount *Counter
	matchLineCount *Counter
	badIPLineCount *Counter
	allowIPCount   *Counter
	watchIPCount   *Counter
	arrestIPCount  *Counter
}

func NewRegexDiscipline(decode Decoder) (Discipliner, error) {
	var rd RegexDiscipline
	if err := decode(&rd); err != nil {
		return nil, err
	}
	id := rd.ID
	if rd.Matches == nil {
		return nil, fmt.Errorf("[discipline-%s] matches is nil", id)
	}
	if err := rd.Matches.ExpectGroups("ip"); err != nil {
		v, _ := rd.Matches.MarshalYAML()
		return nil, fmt.Errorf("[discipline-%s] bad matches: %w, %s", id, err, v)
	}
	rd.tailLinesCount = RegisterNewCounter("discipline", id, "tail_lines")
	rd.matchLineCount = RegisterNewCounter("discipline", id, "match_lines")
	rd.badIPLineCount = RegisterNewCounter("discipline", id, "bad_ip")
	rd.allowIPCount = RegisterNewCounter("discipline", id, "allow_ip")
	rd.watchIPCount = RegisterNewCounter("discipline", id, "watch_ip")
	rd.arrestIPCount = RegisterNewCounter("discipline", id, "arrest_ip")
	return &rd, nil
}

func (rd *RegexDiscipline) Close() error {
	rd.Rate.Stop()
	return nil
}

func (rd *RegexDiscipline) AllowIP(ip net.IP) bool {
	for _, v := range rd.Allows {
		if v.Contains(ip) {
			return true
		}
	}
	return false
}

func (rd *RegexDiscipline) Judge(line Line, allow Allows, logger Logger) (bad BadLog, ok bool) {
	rd.tailLinesCount.Incr()
	if line.Text == "" || rd.Matches == nil {
		ok = false
		return
	}
	groups := rd.Matches.Match(line.Text)
	if len(groups) == 0 {
		logger.Debugf("[discipline-%s][watch-%s] regex not match: length=%d", rd.ID, line.WatchID, len(line.Text))
		ok = false
		return
	}
	if rd.Ignores != nil && rd.Ignores.Test(groups[0].Value) {
		logger.Debugf("[discipline-%s][watch-%s] regex ignore: length=%d", rd.ID, line.WatchID, len(line.Text))
		ok = false
		return
	}
	rd.matchLineCount.Incr()
	ip := net.ParseIP(groups.Get("ip"))
	if ip == nil {
		logger.Debugf("[discipline-%s][watch-%s] no ip group: %s", rd.ID, line.WatchID, groups)
		rd.badIPLineCount.Incr()
		ok = false
		return
	}
	if allow.Contains(ip) || rd.Allows.Contains(ip) {
		rd.allowIPCount.Incr()
		ok = false
		return
	}
	sip := ip.String()
	desc, ok := rd.Rate.Add(sip)
	if ok {
		rd.arrestIPCount.Incr()
		logger.Infof("[discipline-%s][watch-%s] arrest(%s): %s %s", rd.ID, line.WatchID, desc, sip, line.Text)
		bad = NewBadLog(line, rd.ID, ip, groups...)
		return bad, true
	}
	rd.watchIPCount.Incr()
	logger.Infof("[discipline-%s][watch-%s] watch-on(%s): %s %s", rd.ID, line.WatchID, desc, sip, line.Text)
	return bad, false
}
