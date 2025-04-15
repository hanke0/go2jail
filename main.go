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
)

var flags struct {
	LogLevel  int
	LogFile   string
	ConfigDir string
}

func init() {
	flag.StringVar(&flags.LogFile, "log-file", "stderr", "log file definition. support special value: stdout(or -), stderr")
	flag.StringVar(&flags.ConfigDir, "config-dir", "./", "config file directory. load yaml files by lexicographically order.")
	flag.IntVar(&flags.LogLevel, "log-level", LevelWarning, "log level, set debug to error[0,4]")
}

func main() {
	flag.Parse()
	var (
		logger   Logger
		closeLog = func() {}
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
		closeLog = func() {
			f.Close()
		}
		logger = NewLogger(flags.LogLevel, f)
	}

	entries, err := os.ReadDir(flags.ConfigDir)
	if err != nil {
		closeLog()
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
		closeLog()
		log.Fatal("cannot find config in ", flags.ConfigDir)
	}
	cfg, err := Parse(configs...)
	if err != nil {
		closeLog()
		log.Fatal(err)
	}
	stop, err := Start(cfg, logger)
	if err != nil {
		closeLog()
		log.Fatal(err)
	}
	ch := make(chan os.Signal, 1024)
	signal.Notify(ch)
	for range ch {
		stop()
		closeLog()
	}
}

type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type logger struct {
	log   *log.Logger
	level int
}

const (
	LevelDebug = 1 + iota
	LevelInfo
	LevelWarning
	LevelError
)

func NewLogger(level int, output io.Writer) Logger {
	l := logger{
		log:   log.New(output, "", log.Ltime|log.Ldate|log.Lshortfile),
		level: level,
	}
	return &l
}
func (l *logger) Infof(format string, args ...interface{}) {
	if l.level < LevelInfo {
		return
	}
	l.log.Output(3, fmt.Sprintf(format, args...))
}

func (l *logger) Errorf(format string, args ...interface{}) {
	if l.level < LevelError {
		return
	}
	l.log.Output(3, fmt.Sprintf(format, args...))
}
