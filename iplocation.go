package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
)

type IPLocation struct {
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

var spacesReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "")

func (l *IPLocation) String() string {
	if l == nil {
		return ""
	}
	v := fmt.Sprintf("%s-%s-%s", l.Country, l.Region, l.City)
	return spacesReplacer.Replace(v)
}

type IPLocationSources []*IPLocationSource

var ipCache IPLocationCache

func init() {
	ipCache.Init(1024)
}

func (is IPLocationSources) GetLocation(logger Logger, ip net.IP) string {
	if ip == nil || len(is) == 0 {
		return "-"
	}
	if ip.IsLoopback() {
		return "localhost"
	}
	if ip.IsPrivate() {
		return "private"
	}
	if ip.IsLinkLocalUnicast() {
		return "link-local-unicast"
	}
	if ip.IsUnspecified() {
		return "unspecified"
	}
	if ip.IsInterfaceLocalMulticast() {
		return "interface-local-multicast"
	}
	if ip.IsLinkLocalMulticast() {
		return "link-local-multicast"
	}
	if ip.IsMulticast() {
		return "multicast"
	}
	if ip.Equal(net.IPv4bcast) {
		return "broadcast"
	}
	if l := ipCache.Get(ip); l != "" {
		return l
	}
	s := is.getRealLocation(logger, ip)
	if s != "" {
		ipCache.Set(ip, s)
		return s
	}
	return "-"
}

func (is IPLocationSources) getRealLocation(logger Logger, ip net.IP) string {
	var (
		mu          sync.Mutex
		iploc       IPLocation
		cnt         = len(is)
		ctx, cancel = context.WithCancel(context.Background())
		done        = make(chan struct{}, 1)
		sip         = ip.String()
	)
	defer cancel()
	for i, s := range is {
		go func(i int, s *IPLocationSource) {
			loc := s.GetLocation(ctx, logger, sip)
			mu.Lock()
			defer func() {
				cnt--
				if cnt == 0 {
					select {
					case done <- struct{}{}:
					default:
					}
					cancel()
				}
				mu.Unlock()
			}()
			if ctx.Err() != nil {
				return
			}
			if iploc.Country == "" && loc.Country != "" {
				iploc.Country = loc.Country
			}
			if iploc.Region == "" && loc.Region != "" {
				iploc.Region = loc.Region
			}
			if iploc.City == "" && loc.City != "" {
				iploc.City = loc.City
			}
			if iploc.Country != "" && iploc.Region != "" && iploc.City != "" {
				select {
				case done <- struct{}{}:
				default:
				}
				cancel()
			}
		}(i, s)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return iploc.String()
}

type ipLocationSourceYAML struct {
	ID             string `yaml:"id"`
	HTTPHelper     `yaml:",inline"`
	CountryPointer string `yaml:"country_pointer"`
	RegionPointer  string `yaml:"region_pointer"`
	CityPointer    string `yaml:"city_pointer"`
}

type IPLocationSource struct {
	ipLocationSourceYAML `yaml:",inline"`

	countryPointer []string
	regionPointer  []string
	cityPointer    []string
	cache          IPLocationCache
}

func (s *IPLocationSource) UnmarshalYAML(b []byte) error {
	if err := YamlDecode(b, &s.ipLocationSourceYAML); err != nil {
		return err
	}
	if s.ID == "" {
		s.ID = randomID()
	}
	if err := s.HTTPHelper.Init("GET"); err != nil {
		return err
	}
	s.countryPointer = parseJSONPointer(s.CountryPointer)
	s.regionPointer = parseJSONPointer(s.RegionPointer)
	s.cityPointer = parseJSONPointer(s.CityPointer)
	s.cache.Init(1024)
	return nil
}

func randomID() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
	var bs strings.Builder
	for range 8 {
		i := rand.Intn(len(letterBytes))
		bs.WriteByte(letterBytes[i])
	}
	return bs.String()
}

/*
Evaluation of each reference token begins by decoding any escaped
character sequence.  This is performed by first transforming any
occurrence of the sequence '~1' to '/', and then transforming any
occurrence of the sequence '~0' to '~'.  By performing the
substitutions in this order, an implementation avoids the error of
turning '~01' first into '~1' and then into '/', which would be
incorrect (the string '~01' correctly becomes '~1' after
transformation).
*/
var unescapeReplace = strings.NewReplacer("~1", "/", "~0", "~")

func unescapePath(path string) string {
	return unescapeReplace.Replace(path)
}

func parseJSONPointer(s string) []string {
	if s == "" {
		return nil
	}
	v := strings.Split(s, "/")
	if v[0] != "" {
		return nil
	}
	var r []string
	for _, d := range v[1:] {
		r = append(r, unescapePath(d))
	}
	return r
}

// visitJSON by json pointer introduced by https://datatracker.ietf.org/doc/html/rfc6901
func visitJSON(object any, path ...string) string {
	for _, p := range path {
		switch mt := object.(type) {
		case map[string]any:
			if v, ok := mt[p]; ok {
				object = v
			} else {
				return ""
			}
		case []any:
			if len(mt) == 0 {
				return ""
			}
			if p == "-" {
				object = mt[len(mt)-1]
				continue
			}
			i, err := strconv.Atoi(p)
			if err != nil {
				return ""
			}
			if i < 0 {
				i = len(mt) + i
			}
			if i < 0 || i >= len(mt) {
				return ""
			}
			object = mt[i]
		default:
			return ""
		}
	}
	if object == nil {
		return ""
	}
	switch v := object.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func (s *IPLocationSource) GetLocation(ctx context.Context, logger Logger, ip string) (loc IPLocation) {
	c, err := s.HTTPHelper.Do(ctx, true,
		func(s string) string {
			if s == "ip" {
				return ip
			}
			return ""
		})
	if err != nil {
		logger.Debugf("get ip location http response error: %s %v", ip, err)
		return
	}
	var object any
	if err := json.Unmarshal(c, &object); err != nil {
		logger.Debugf("get ip location unmarshal error: %s %v", ip, err)
		return
	}
	logger.Debugf("get ip location json: %s %s", ip, c)
	loc.Country = visitJSON(object, s.countryPointer...)
	loc.Region = visitJSON(object, s.regionPointer...)
	loc.City = visitJSON(object, s.cityPointer...)
	logger.Debugf("get parsed ip location: %s %s", ip, loc)
	return
}

type FixedIP [16]byte

type IPLocationCache struct {
	sync.RWMutex
	data  map[FixedIP]int
	value []string
}

func (i *IPLocationCache) Init(size int) {
	i.data = make(map[FixedIP]int, size)
	i.value = make([]string, 0, size)
}

func (s *IPLocationCache) Get(ip net.IP) string {
	s.RLock()
	defer s.RUnlock()
	fixedIP := FixedIP(ip)
	i, ok := s.data[fixedIP]
	if !ok {
		return ""
	}
	return s.value[i]
}

func (s *IPLocationCache) Set(ip net.IP, value string) {
	s.Lock()
	defer s.Unlock()
	fixedIP := FixedIP(ip)
	if idx, ok := s.data[fixedIP]; ok {
		s.value[idx] = value
		return
	}
	if len(s.value) == cap(s.value) {
		var (
			key FixedIP
			idx int
		)
		for key, idx = range s.data {
			break
		}
		delete(s.data, key)
		s.data[fixedIP] = idx
		s.value[idx] = value
		return
	}
	idx := len(s.data)
	s.data[fixedIP] = idx
	s.value = s.value[:idx+1]
	s.value[idx] = value
}
