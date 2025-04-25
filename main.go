package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

var (
	shortUsage   = `Usage: go2jail <command> [command option]...`
	badUsageHelp = `Try 'go2jail --help' for more information.`
)

var usageDescription = `go2jail is a daemon used to ban hosts attempting to attack your server.`

var (
	Version   = "v0.0.1-unknown"
	Rev       = "unknown-rev"
	GoVersion = "unknown-go"
	BuildTime = "unknown-time"
)

func printVersion() {
	fmt.Printf("go2jail %s (%s) build by %s at %s\n", Version, Rev, GoVersion, BuildTime)
}

var (
	commands   []commander
	globalFlag flag.FlagSet
)

func init() {
	commands = append(commands,
		&runDaemonCommand,
		&testDisciplineCommand,
		&testRegexCommand,
		&testConfigCommand,
		&testMailCommand,
	)
	for _, c := range commands {
		c.init()
	}
	globalFlag.Usage = func() {
		fmt.Fprintln(globalFlag.Output(), shortUsage)
		fmt.Fprintln(globalFlag.Output(), usageDescription)
		fmt.Fprintln(globalFlag.Output())
		fmt.Fprintln(globalFlag.Output(), "COMMANDS:")
		fmt.Fprintln(globalFlag.Output(), "    -h, --help       print this message and exit.")
		fmt.Fprintln(globalFlag.Output(), "    -v, --version    print version and exit.")
		max := len("-v, --version    ")

		for _, cmd := range commands {
			fmt.Fprintln(globalFlag.Output(), "    "+cmd.name()+strings.Repeat(" ", max-len(cmd.name()))+cmd.shortDescription())
		}
	}
}

type runDaemonOption struct {
	logFlags
	configFlags
	HTTPStatsListenAddr string

	logger Logger
}

var runDaemonCommand = Command[runDaemonOption]{
	Name:             "run",
	ShortDescription: "run the daemon with specific config.",
	Init: func(c *Command[runDaemonOption]) {
		c.Options.configFlags.init(&c.FlagSet)
		c.Options.logFlags.init(&c.FlagSet)
		c.FlagSet.StringVar(&c.Options.HTTPStatsListenAddr, "http-stats-listen-addr", "", "http stats listen address")
	},
	Run: func(c *Command[runDaemonOption]) error {
		opt := &c.Options
		wait, stop, err := runDaemon(opt)
		if err != nil {
			return err
		}
		waitAndHandleSignal(wait, stop)
		c.Options.logger.Infof("daemon stopped")
		return nil
	},
}

type testDisciplineOption struct {
	logFlags
	configFlags
}

var testDisciplineCommand = Command[testDisciplineOption]{
	Name:             "test",
	ShortUsage:       "test [OPTION]... <discipline-id>",
	ShortDescription: "find out what should be banned based on a discipline.",
	LongDescription:  "It's usually a good idea to test a single discipline before it is enabled.",
	NArgs:            1,
	Init: func(c *Command[testDisciplineOption]) {
		c.Options.configFlags.init(&c.FlagSet)
		c.Options.logFlags.init(&c.FlagSet)
	},
	Run: func(c *Command[testDisciplineOption]) error {
		opt := &c.Options
		wait, stop, err := runTestDiscipline(opt, c.FlagSet.Arg(0))
		if err != nil {
			return err
		}
		waitAndHandleSignal(wait, stop)
		return nil
	},
}

type testConfigOptions struct {
	configFlags
}

var testConfigCommand = Command[testConfigOptions]{
	Name:             "test-config",
	ShortDescription: "test you config.",
	Init: func(c *Command[testConfigOptions]) {
		opt := &c.Options
		flag := &c.FlagSet
		opt.configFlags.init(flag)
	},
	Run: func(c *Command[testConfigOptions]) error {
		_, err := c.Options.configFlags.getConfig()
		return err
	},
}

type testRegexOptions struct {
	TestRegexMatch  Multi
	TestRegexIgnore Multi
}

var testRegexCommand = Command[testRegexOptions]{
	Name:             "regex",
	ShortUsage:       "regex [OPTION]... <FILE>",
	ShortDescription: "test you regex pattern.",
	NArgs:            1,
	Init: func(c *Command[testRegexOptions]) {
		opt := &c.Options
		flag := &c.FlagSet
		flag.Var(&opt.TestRegexMatch, "match", "match pattern, could provides many times.")
		flag.Var(&opt.TestRegexIgnore, "ignore", "ignore pattern, could provides many times.")
	},
	Run: func(c *Command[testRegexOptions]) error {
		return runTestRegex(&c.Options, c.FlagSet.Arg(0))
	},
}

type testMailOptions struct {
	configFlags
	logFlags
	JailID string
}

var testMailCommand = Command[testMailOptions]{
	Name:             "test-mail",
	ShortUsage:       "test-mail [OPTION]... <jail-id> [jail-id]...",
	ShortDescription: "test mail smtp connect by sending a connect mail.",
	NArgs:            -1,
	Init: func(c *Command[testMailOptions]) {
		c.Options.configFlags.init(&c.FlagSet)
		c.Options.logFlags.init(&c.FlagSet)
	},
	Run: func(c *Command[testMailOptions]) error {
		if c.FlagSet.NArg() == 0 {
			return fmt.Errorf("No jail id provided. \n%s", badUsageHelp)
		}
		return runTestMail(&c.Options, c.FlagSet.Args()...)
	},
}

type Command[T any] struct {
	Name             string
	ShortUsage       string
	ShortDescription string
	LongDescription  string
	FlagSet          flag.FlagSet
	Options          T
	NArgs            int
	Init             func(*Command[T])
	Run              func(*Command[T]) error
}

func (c *Command[T]) name() string {
	return c.Name
}

func (c *Command[T]) run(args []string) error {
	if err := c.FlagSet.Parse(args); err != nil {
		return err
	}
	if c.NArgs >= 0 {
		if c.FlagSet.NArg() < c.NArgs {
			return fmt.Errorf("Too few arguments. \n%s", badUsageHelp)
		}
		if c.FlagSet.NArg() > c.NArgs {
			return fmt.Errorf("Too many arguments. \n%s", badUsageHelp)
		}
	}
	return c.Run(c)
}

func (c *Command[T]) init() {
	c.FlagSet.Init(c.Name, flag.ExitOnError)
	c.FlagSet.Usage = c.usage
	c.Init(c)
}

func (c *Command[T]) usage() {
	if c.ShortUsage == "" {
		switch c.NArgs {
		case 0:
			c.ShortUsage = c.Name + " [OPTION]..."
		case 1:
			c.ShortUsage = c.Name + " [OPTION]... <ARG>"
		default:
			if c.NArgs > 0 {
				c.ShortUsage = fmt.Sprintf("%s [OPTION]... <ARG>{%d}", c.Name, c.NArgs)
			} else {
				c.ShortUsage = c.Name + " [OPTION]... <ARG>..."
			}
		}
	}
	fmt.Fprintln(c.FlagSet.Output(), "Usage: go2jail", c.ShortUsage)
	fmt.Fprintln(c.FlagSet.Output(), c.ShortDescription)
	fmt.Fprintln(c.FlagSet.Output(), c.LongDescription)
	fmt.Fprintln(c.FlagSet.Output())
	fmt.Fprintln(c.FlagSet.Output(), "OPTIONS:")
	c.FlagSet.PrintDefaults()
}

func (c *Command[T]) shortDescription() string {
	return c.ShortDescription
}

var _ commander = (*Command[any])(nil)

type commander interface {
	name() string
	run(args []string) error
	init()
	shortDescription() string
	usage()
}

type logFlags struct {
	LogLevel string
	LogFile  string
}

func (flags *logFlags) init(flag *flag.FlagSet) {
	flag.StringVar(&flags.LogFile, "log-file", "stderr", "log file definition. support special value: stdout(or -), stderr")
	flag.StringVar(&flags.LogLevel, "log-level", "info", "log level, debug,info,warning,error")
}

func (flags *logFlags) getLogger() (logger Logger, clean func(), err error) {
	level, err := parseLevel(flags.LogLevel)
	if err != nil {
		return nil, nil, fmt.Errorf("bad log level: %w", err)
	}
	clean = nothing
	switch flags.LogFile {
	case "stdout", "-":
		logger = NewLogger(level, Stdout)
	case "stderr", "":
		logger = NewLogger(level, Stderr)
	default:
		f, err := os.OpenFile(flags.LogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Fatal(err)
		}
		clean = func() {
			f.Close()
		}
		logger = NewLogger(level, f)
	}
	return logger, clean, nil
}

type configFlags struct {
	ConfigDir    string
	StrictConfig bool
}

func (flags *configFlags) init(flag *flag.FlagSet) {
	flag.StringVar(&flags.ConfigDir, "config-dir", "./", "config file directory. load yaml files by lexicographically order.")
	flag.BoolVar(&flags.StrictConfig, "strict-config", false, "check config strict")
}

func (flags *configFlags) getConfig() (*Config, error) {
	if flags.StrictConfig {
		YAMLStrict = true
	}
	entries, err := os.ReadDir(flags.ConfigDir)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("cannot find config in %s", flags.ConfigDir)
	}
	return Parse(configs...)
}

func entrypoint(args []string) error {
	if len(args) == 0 {
		globalFlag.Usage()
		return fmt.Errorf("%s\n", shortUsage)
	}
	cmd := args[0]
	args = args[1:]
	switch cmd {
	case "version", "-v", "--version":
		printVersion()
		return nil
	case "-h", "--help":
		globalFlag.Usage()
		return nil
	default:
		for _, c := range commands {
			if c.name() == cmd {
				return c.run(args)
			}
		}
		return fmt.Errorf("unknown command: %s\n%s", cmd, badUsageHelp)
	}
}

func main() {
	if err := entrypoint(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func waitAndHandleSignal(wait, stop func()) {
	ch := make(chan os.Signal, 1024)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-ch
		fmt.Fprintf(os.Stderr, "receive signal %s, stopping...\n", s)
		stop()
	}()
	wait()
}

var (
	Stdout io.Writer = os.Stdout
	Stderr io.Writer = os.Stderr
)

func parseLevel(s string) (int, error) {
	switch s {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warning":
		return LevelWarning, nil
	case "error":
		return LevelError, nil
	default:
		return strconv.Atoi(s)
	}
}

func runDaemon(opt *runDaemonOption) (wait, stop func(), err error) {
	cfg, err := opt.configFlags.getConfig()
	if err != nil {
		return nil, nil, err
	}
	logger, clean, err := opt.logFlags.getLogger()
	if err != nil {
		return nil, nil, err
	}
	var stops Finisher
	stops.Push(clean)

	wait, stop, err1 := Start(cfg, logger, "", opt.HTTPStatsListenAddr)
	if err1 != nil {
		stops.Finish()
		return nil, nil, err1
	}
	stops.Push(stop)
	logger.Infof("daemon started")
	opt.logger = logger
	return wait, stops.Finish, nil
}

func runTestDiscipline(opt *testDisciplineOption, id string) (wait, stop func(), err error) {
	if id == "" {
		return nil, nil, fmt.Errorf("not provided discipline id")
	}
	cfg, err := opt.configFlags.getConfig()
	if err != nil {
		return nil, nil, err
	}
	ok := slices.ContainsFunc(cfg.Disciplines, func(d *Discipline) bool {
		return d.ID == id
	})
	if !ok {
		return nil, nil, fmt.Errorf("discipline not found: %s", id)
	}
	logger, clean, err := opt.logFlags.getLogger()
	if err != nil {
		return nil, nil, err
	}
	var stops Finisher
	stops.Push(clean)

	wait, stop, err1 := Start(cfg, logger, id, "")
	if err1 != nil {
		stops.Finish()
		return nil, nil, err1
	}
	stops.Push(stop)
	return wait, stops.Finish, nil
}

func runTestRegex(flags *testRegexOptions, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	b, _ := json.Marshal(flags.TestRegexMatch.Values)
	var (
		match   Matcher
		ignores Matcher
	)
	if err := match.UnmarshalYAML(b); err != nil {
		return err
	}
	if err := match.ExpectGroups("ip"); err != nil {
		return err
	}
	if flags.TestRegexIgnore.Values != nil {
		b, _ := json.Marshal(flags.TestRegexIgnore.Values)
		if err := ignores.UnmarshalYAML(b); err != nil {
			return err
		}
	}

	fmt.Println(match.MarshalYAML())
	fmt.Println(ignores.MarshalYAML())

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		g := match.Match(line)
		if len(g) > 0 && !ignores.Test(line) {
			fmt.Println("MATCH\t" + g.String())
		} else {
			fmt.Println("MISS:\t", line)
		}
	}
	return scan.Err()
}

func runTestMail(cfg *testMailOptions, id ...string) error {
	c, err := cfg.configFlags.getConfig()
	if err != nil {
		return err
	}
	logger, clean, err := cfg.logFlags.getLogger()
	if err != nil {
		return err
	}
	defer clean()
	var stops Finisher
	stops.Push(clean)
	defer stops.Finish()
	const subject = "go2jail connection test"
	const body = `<div id="root"><p>This email is just a test of the SMTP connection.<p>You may ignore it.</p></div>`
	for _, v := range c.Jails {
		if m, ok := v.Action.(Mailer); ok && slices.Contains(id, v.ID) {
			if err := m.SendMail(logger, subject, body); err != nil {
				fmt.Println("MAIL TESTING FAIL: ", v.ID)
				return err
			}
			fmt.Println("MAIL TESTING OK: ", v.ID)
		}
	}
	return nil
}

type Multi struct {
	Values []string
}

var _ flag.Getter = (*Multi)(nil)

func (m *Multi) String() string {
	return ""
}

func (m *Multi) Get() any {
	return m.Values
}

func (m *Multi) Set(value string) error {
	m.Values = append(m.Values, value)
	return nil
}

func nothing() {}
