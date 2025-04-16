package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

type Flags struct {
	LogLevel       int
	LogFile        string
	ConfigDir      string
	TestDiscipline string
	TestConfig     bool
	Version        bool
}

var flags Flags

func init() {
	flag.StringVar(&flags.LogFile, "log-file", "stderr", "log file definition. support special value: stdout(or -), stderr")
	flag.StringVar(&flags.ConfigDir, "config-dir", "./", "config file directory. load yaml files by lexicographically order.")
	flag.StringVar(&flags.TestDiscipline, "test-discipline", "", "test discipline id")
	flag.BoolVar(&flags.TestConfig, "test-config", false, "test config file")
	flag.BoolVar(&flags.Version, "version", false, "show version")
	flag.IntVar(&flags.LogLevel, "log-level", LevelWarning, "log level, set debug to error[0,4]")
}

var (
	Version   = "v0.0.1-unknown"
	Rev       = "unknown-rev"
	GoVersion = "unknown-go"
	BuildTime = "unknown-time"
)

func printVersion() {
	fmt.Printf("go2jail %s (%s) build by %s at %s\n", Version, Rev, GoVersion, BuildTime)
}

func main() {
	flag.Parse()
	if flags.Version {
		printVersion()
		return
	}
	wait, stop, err := entry(&flags)
	if err != nil {
		log.Fatal(err)
	}
	ch := make(chan os.Signal, 1024)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-ch
		log.Printf("receive signal %s, stopping...", s)
		stop()
	}()
	wait()
}

var (
	Stdout io.Writer = os.Stdout
	Stderr io.Writer = os.Stderr
)

func entry(flags *Flags) (wait, stop func(), err error) {
	var (
		logger  Logger
		cleaner Cleaner
	)

	switch flags.LogFile {
	case "stdout", "-":
		logger = NewLogger(flags.LogLevel, Stdout)
	case "stderr", "":
		logger = NewLogger(flags.LogLevel, Stderr)
	default:
		f, err := os.OpenFile(flags.LogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Fatal(err)
		}
		cleaner.Push(func() {
			f.Close()
		})
		logger = NewLogger(flags.LogLevel, f)
	}

	entries, err := os.ReadDir(flags.ConfigDir)
	if err != nil {
		cleaner.Clean()
		return nil, nil, err
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
		cleaner.Clean()
		return nil, nil, fmt.Errorf("cannot find config in %s", flags.ConfigDir)
	}
	cfg, err := Parse(configs...)
	if err != nil {
		cleaner.Clean()
		return nil, nil, err
	}
	if flags.TestConfig {
		cleaner.Clean()
		return nothing, nothing, nil
	}
	stop, wait, err1 := Start(cfg, logger, flags.TestDiscipline)
	if err1 != nil {
		cleaner.Clean()
		return nil, nil, err1
	}
	cleaner.Push(stop)
	return wait, cleaner.Clean, nil
}

func nothing() {}
