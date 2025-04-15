package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

var flags struct {
	LogLevel   int
	LogFile    string
	ConfigDir  string
	Test       string
	TestConfig bool
}

func init() {
	flag.StringVar(&flags.LogFile, "log-file", "stderr", "log file definition. support special value: stdout(or -), stderr")
	flag.StringVar(&flags.ConfigDir, "config-dir", "./", "config file directory. load yaml files by lexicographically order.")
	flag.StringVar(&flags.Test, "test", "", "test discipline id")
	flag.BoolVar(&flags.TestConfig, "test-config", false, "test config file")
	flag.IntVar(&flags.LogLevel, "log-level", LevelWarning, "log level, set debug to error[0,4]")
}

var stops []func()

func atexit(fn func()) {
	stops = append(stops, fn)
}

func cleanup() {
	for _, s := range stops {
		s()
	}
}

func main() {
	flag.Parse()
	var (
		logger Logger
	)
	switch flags.LogFile {
	case "stdout", "-":
		logger = NewLogger(flags.LogLevel, os.Stdout)
	case "stderr":
		logger = NewLogger(flags.LogLevel, os.Stdout)
	default:
		f, err := os.OpenFile(flags.LogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Fatal(err)
		}
		atexit(func() {
			f.Close()
		})
		logger = NewLogger(flags.LogLevel, f)
	}

	entries, err := os.ReadDir(flags.ConfigDir)
	if err != nil {
		cleanup()
		log.Fatal(err)
	}
	var configs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			configs = append(configs, filepath.Join(flags.ConfigDir, e.Name()))
		}
	}
	if len(configs) == 0 {
		cleanup()
		log.Fatal("cannot find config in ", flags.ConfigDir)
	}
	cfg, err := Parse(configs...)
	if err != nil {
		cleanup()
		log.Fatal(err)
	}
	if flags.TestConfig {
		cleanup()
		return
	}

	stop, wait, err := Start(cfg, logger, flags.Test)
	if err != nil {
		cleanup()
		log.Fatal(err)
	}
	ch := make(chan os.Signal, 1024)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-ch
		logger.Infof("receive signal %s, stopping...", s)
		stop()
	}()
	wait()
	cleanup()
}
