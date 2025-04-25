package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

func init() {
	RegisterJail("nftset", NewNftJail)
	RegisterJail("echo", NewEchoJail)
	RegisterJail("log", NewLogJail)
	RegisterJail("shell", NewShellJail)
	RegisterJail("http", NewHTTPJail)
	RegisterJail("mail", NewMailJail)
}

type NftJail struct {
	BaseJail      `yaml:",inline"`
	Sudo          bool   `yaml:"sudo"`
	NftExecutable string `yaml:"nft_executable"`
	Rule          string `yaml:"rule"`
	Table         string `yaml:"table"`
	IPv4Set       string `yaml:"ipv4_set"`
	IPv6Set       string `yaml:"ipv6_set"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewNftJail(decode Decoder) (Jailer, error) {
	var j NftJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	nft := j.NftExecutable
	if nft == "" {
		nft = "nft"
	}
	p, err := exec.LookPath(nft)
	if err != nil {
		return nil, fmt.Errorf("can not find nft executable: %w", err)
	}
	j.NftExecutable = p
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (nj *NftJail) Arrest(bad BadLog, log Logger) error {
	var (
		s   string
		set string
		ip  = bad.IP
	)
	if ip.To4() != nil {
		s = ip.To4().String()
		set = nj.IPv4Set
	} else {
		s = ip.To16().String()
		set = nj.IPv6Set
	}
	var program []string
	if nj.Sudo {
		program = []string{"sudo"}
	}
	program = append(program,
		nj.NftExecutable,
		"add",
		"element",
		nj.Rule,
		nj.Table,
		set,
		"{",
		s,
		"}",
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	cmd := exec.CommandContext(ctx, program[0], program[1:]...)
	buf := NewRingBuffer(defaultScriptOutputSize)
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w, args=%s, output=%s", err, program, buf.String())
		nj.jailFailCounter.Incr()
	} else {
		nj.jailSuccessCounter.Incr()
	}
	return err
}

func (nj *NftJail) Close() error {
	return nil
}

type EchoJail struct {
	BaseJail           `yaml:",inline"`
	jailSuccessCounter *Counter `yaml:"-"`
}

func NewEchoJail(decode Decoder) (Jailer, error) {
	var j EchoJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	return &j, nil
}

var testDisciplineJail *Jail

func init() {
	var j Jail
	err := j.UnmarshalYAML([]byte(`id: test-config
type: echo`))
	if err != nil {
		panic(err)
	}
	testDisciplineJail = &j
}

func (ej *EchoJail) Arrest(bad BadLog, log Logger) error {
	fmt.Fprintln(Stdout, bad.IP.String(), bad.Line)
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *EchoJail) Close() error {
	return nil
}

type LogJail struct {
	BaseJail `yaml:",inline"`

	jailSuccessCounter *Counter `yaml:"-"`
}

func NewLogJail(decode Decoder) (Jailer, error) {
	var j LogJail
	err := decode(&j)
	if err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	return &j, nil
}

func (ej *LogJail) Arrest(bad BadLog, log Logger) error {
	log.Infof("[jail-%s] arrest ip %s, groups=%s", ej.ID, bad.IP, bad.Extend.String())
	ej.jailSuccessCounter.Incr()
	return nil
}

func (ej *LogJail) Close() error {
	return nil
}

type Options struct {
}

type ShellJail struct {
	BaseJail         `yaml:",inline"`
	Run              string `yaml:"run"`
	YAMLScriptOption `yaml:",inline"`

	jailSuccessCounter *Counter `yaml:"-"`
	jailFailCounter    *Counter `yaml:"-"`
}

func NewShellJail(decode Decoder) (Jailer, error) {
	var j ShellJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	if err := j.YAMLScriptOption.SetupShell(); err != nil {
		return nil, err
	}
	j.jailSuccessCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_success", j.ID))
	j.jailFailCounter = RegisterNewCounter(fmt.Sprintf("%s_jail_fail", j.ID))
	return &j, nil
}

func (sj *ShellJail) Arrest(bad BadLog, log Logger) error {
	opt := ScriptOption{
		YAMLScriptOption: sj.YAMLScriptOption,
		Env:              bad.Extend.AsEnv(),
	}
	out, err := RunScript(sj.Run, &opt, bad.IP.String(), bad.Line)
	if err != nil {
		err = fmt.Errorf("%w, output=%s", err, out)
		sj.jailFailCounter.Incr()
		return err
	}
	sj.jailSuccessCounter.Incr()
	return nil
}

func (sj *ShellJail) Close() error {
	return nil
}

type HTTPJail struct {
	BaseJail `yaml:",inline"`
	URL      string     `yaml:"url"`
	Method   string     `yaml:"method"`
	Args     []KeyValue `yaml:"args"`
	Headers  []KeyValue `yaml:"headers"`
	Body     string     `yaml:"body"`
}

func NewHTTPJail(decode Decoder) (Jailer, error) {
	var j HTTPJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	_, err := url.Parse(j.URL)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w, %s", err, j.URL)
	}
	if j.Method == "" {
		j.Method = http.MethodPost
	}
	return &j, nil
}

func (hj *HTTPJail) Arrest(bad BadLog, log Logger) error {
	log.Debugf("[jail-%s] start arrest ip %s", hj.ID, bad.IP)
	body := bad.Extend.Expand(hj.Body)
	url := bad.Extend.Expand(hj.URL)
	req, err := http.NewRequest(hj.Method, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	for _, entry := range hj.Headers {
		req.Header.Add(entry.Key, bad.Extend.Expand(entry.Value))
	}
	query := req.URL.Query()
	for _, entry := range hj.Args {
		query.Add(entry.Key, bad.Extend.Expand(entry.Value))
	}
	req.URL.RawQuery = query.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body := io.LimitReader(resp.Body, 1024)
		b, _ := io.ReadAll(body)
		return fmt.Errorf("http status code %d, body=%s", resp.StatusCode, string(b))
	}
	return nil
}

func (hj *HTTPJail) Close() error {
	return nil
}

type MailJail struct {
	BaseJail     `yaml:",inline"`
	Host         string
	From         string `yaml:"from"`
	To           string `yaml:"to"`
	Subject      string `yaml:"subject"`
	Body         string `yaml:"body"`
	Encryption   string `yaml:"encryption"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"`

	realPass    string `yaml:"-"`
	serverName  string
	fromAddress string
	toAddresses []string
}

func NewMailJail(decode Decoder) (Jailer, error) {
	var j MailJail
	if err := decode(&j); err != nil {
		return nil, err
	}
	m, err := mail.ParseAddress(j.From)
	if err != nil {
		return nil, fmt.Errorf("bad from: %w, %s", err, j.From)
	}
	j.From = m.String()
	j.fromAddress = m.Address
	to, err := mail.ParseAddressList(j.To)
	if err != nil {
		return nil, fmt.Errorf("bad to: %w, %s", err, j.To)
	}
	var bs strings.Builder
	for _, tt := range to {
		j.toAddresses = append(j.toAddresses, tt.Address)
		if bs.Len() > 0 {
			bs.WriteString(", ")
		}
		bs.WriteString(tt.String())
	}
	j.To = bs.String()
	if j.PasswordFile != "" {
		b, err := os.ReadFile(j.PasswordFile)
		if err != nil {
			return nil, err
		}
		j.realPass = string(b)
	} else {
		j.realPass = j.Password
	}
	if j.realPass == "" || j.Username == "" {
		return nil, errors.New("username or password is empty")
	}
	host, _, err := net.SplitHostPort(j.Host)
	if err != nil {
		return nil, fmt.Errorf("bad host: %w, %s", err, j.Host)
	}
	j.serverName = host
	switch j.Encryption {
	case "":
		j.Encryption = "tls"
	case "tls", "ssl", "starttls":
	default:
		return nil, fmt.Errorf("unknown encryption method: %s", j.Encryption)
	}
	return &j, nil
}

func (mj *MailJail) Arrest(bad BadLog, log Logger) error {
	body := bad.Extend.Expand(mj.Body)
	subject := bad.Extend.Expand(mj.Subject)
	err := mj.SendMail(log, subject, body)
	return err
}

type Mailer interface {
	SendMail(logger Logger, subject, body string) error
}

var _ Mailer = (*MailJail)(nil)

func (mj *MailJail) SendMail(logger Logger, subject, body string) error {
	var (
		client *smtp.Client
		dialer net.Dialer
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	dialer.Deadline = deadline
	tlscfg := &tls.Config{
		ServerName: mj.serverName,
	}
	switch mj.Encryption {
	case "tls", "ssl":
		conn, err := tls.DialWithDialer(&dialer, "tcp", mj.Host, tlscfg)
		if err != nil {
			logger.Debugf("dial error: %v", err)
			return err
		}
		if err := conn.SetDeadline(deadline); err != nil {
			logger.Debugf("set deadline error: %v", err)
			return err
		}
		c, err := smtp.NewClient(conn, mj.serverName)
		if err != nil {
			logger.Debugf("new smtp client err: %v", err)
			return err
		}
		client = c
	case "starttls":
		conn, err := dialer.Dial("tcp", mj.Host)
		if err != nil {
			logger.Debugf("dial error: %v", err)
			return err
		}
		if err := conn.SetDeadline(deadline); err != nil {
			logger.Debugf("set deadline error: %v", err)
			return err
		}
		c, err := smtp.NewClient(conn, mj.serverName)
		if err != nil {
			logger.Debugf("new smtp client err: %v", err)
			return err
		}
		if err := client.StartTLS(tlscfg); err != nil {
			logger.Debugf("start tls error: %v", err)
			c.Close()
			return err
		}
		client = c
	default:
		return fmt.Errorf("unknown encryption: %s", mj.Encryption)
	}

	defer client.Close()
	if err := client.Auth(smtp.PlainAuth("", mj.Username, mj.realPass, mj.serverName)); err != nil {
		logger.Debugf("auth error: %v", err)
		return err
	}
	if err := client.Mail(mj.fromAddress); err != nil {
		logger.Debugf("mail error: %v", err)
		return err
	}
	for _, to := range mj.toAddresses {
		if err := client.Rcpt(to); err != nil {
			logger.Debugf("rcpt error: %s %v", to, err)
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		logger.Debugf("data error: %v", err)
		return err
	}
	if _, err := fmt.Fprintf(w, "Date: %s\r\n", time.Now().UTC().Format(http.TimeFormat)); err != nil {
		logger.Debugf("write header date error: %v", err)
		return err
	}
	if _, err := fmt.Fprintf(w, "SUBJECT: %s\r\n", mime.BEncoding.Encode("UTF-8", subject)); err != nil {
		logger.Debugf("write header subject error: %v", err)
		return err
	}
	if _, err := fmt.Fprintf(w, "FROM: %s\r\n", mj.From); err != nil {
		logger.Debugf("write header from error: %v", err)
		return err
	}
	if _, err := fmt.Fprintf(w, "TO: %s\r\n", mj.To); err != nil {
		logger.Debugf("write header to error: %v", err)
		return err
	}
	if _, err := io.WriteString(w, "MIME-Version: 1.0\r\n"); err != nil {
		logger.Debugf("write header mime-version error: %v", err)
		return err
	}
	mw := multipart.NewWriter(w)
	contentType := mime.FormatMediaType("multipart/mixed", map[string]string{
		"boundary": mw.Boundary(),
	})
	if _, err := fmt.Fprintf(w, "Content-Type: %s\r\n\r\n", contentType); err != nil {
		logger.Debugf("write header content-type error: %v", err)
		return err
	}
	p, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              []string{"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": []string{"base64"},
	})
	if err != nil {
		logger.Debugf("create multi part error: %v", err)
		return err
	}
	enc := base64.NewEncoder(base64.StdEncoding, p)
	if _, err := io.WriteString(enc, body); err != nil {
		logger.Debugf("write body error: %v", err)
		return err
	}
	if err := enc.Close(); err != nil {
		logger.Debugf("close body error: %v", err)
		return err
	}
	if err := mw.Close(); err != nil {
		logger.Debugf("close multi part error: %v", err)
		return err
	}
	if _, err := fmt.Fprintf(w, "\r\n"); err != nil {
		logger.Debugf("write crlf error: %v", err)
		return err
	}
	if err := w.Close(); err != nil {
		logger.Debugf("close data error: %v", err)
		return err
	}
	if err := client.Quit(); err != nil {
		logger.Debugf("quit error: %v", err)
		return err
	}
	return nil
}

func (mj *MailJail) Close() error {
	return nil
}
