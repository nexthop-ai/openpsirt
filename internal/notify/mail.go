package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Channel carries a message to somebody outside the application.
//
// One interface for every channel there will be, so that a third is an adapter
// rather than a second implementation of what to say: what may be said is
// decided in Compose, and a channel decides only how to carry it.
type Channel interface {
	// Name is what this channel is called in a log line.
	Name() string
	// Send carries one message to one address. An error is a reason to try
	// again later rather than to give up: what is unsent stays unsent.
	Send(ctx context.Context, to string, m Message) error
}

// Mail carries messages over SMTP.
//
// Configured by an operator or absent entirely. A deployment that never
// configured mail is the ordinary case rather than a broken one — which is why
// the notification area exists and needs nothing set up.
type Mail struct {
	addr     string
	from     string
	username string
	password string
	// timeout bounds the whole conversation with the server. Without it a
	// server that accepts a connection and then says nothing holds the sweep
	// for as long as it likes, and the sweep is what carries everything else.
	timeout time.Duration
}

// NewMail returns a channel over the SMTP server at addr, or nil where the
// deployment has not configured one.
//
// Nil rather than an error: not configuring mail is a choice an operator is
// entitled to make, and the tool works without it.
func NewMail(addr, from, username, password string) *Mail {
	addr, from = strings.TrimSpace(addr), strings.TrimSpace(from)
	if addr == "" || from == "" {
		return nil
	}
	return &Mail{
		addr: addr, from: from,
		username: strings.TrimSpace(username), password: password,
		timeout: 30 * time.Second,
	}
}

// Name is what this channel is called in a log line.
func (m *Mail) Name() string { return "mail" }

// Send carries one message to one address.
//
// STARTTLS where the server offers it, and credentials only over a connection
// that has been secured — a password sent in the clear to whatever answered on
// that port is a password given away, and an operator who configured one is
// entitled to assume it is not.
func (m *Mail) Send(ctx context.Context, to string, message Message) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("no address to send to")
	}

	dialer := &net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return fmt.Errorf("reach the mail server at %s: %w", m.addr, err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(m.timeout))
	}

	host, _, err := net.SplitHostPort(m.addr)
	if err != nil {
		host = m.addr
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("start talking to the mail server: %w", err)
	}
	defer func() { _ = client.Quit() }()

	secured := false
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("secure the connection to the mail server: %w", err)
		}
		secured = true
	}
	if m.username != "" {
		if !secured {
			return errors.New("the mail server offered no STARTTLS, and a password " +
				"sent in the clear is a password given away")
		}
		if err := client.Auth(smtp.PlainAuth("", m.username, m.password, host)); err != nil {
			return fmt.Errorf("sign in to the mail server: %w", err)
		}
	}

	if err := client.Mail(m.from); err != nil {
		return fmt.Errorf("start a message: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("address a message to %q: %w", to, err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("write a message: %w", err)
	}
	if _, err := writer.Write(headers(m.from, to, message)); err != nil {
		return fmt.Errorf("write a message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish a message: %w", err)
	}
	return nil
}

// headers renders the message as the bytes a server is given.
//
// The subject is encoded rather than written through, because it comes from
// this application's own words today and from a finding's one day, and a
// header is not a place to discover that something contained a newline.
func headers(from, to string, m Message) []byte {
	var out strings.Builder
	out.WriteString("From: " + sanitizedHeader(from) + "\r\n")
	out.WriteString("To: " + sanitizedHeader(to) + "\r\n")
	out.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", oneLine(m.Subject)) + "\r\n")
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	out.WriteString("\r\n")
	out.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))
	return []byte(out.String())
}

// sanitizedHeader keeps an address to one line.
//
// A newline in a header is how a second header is injected, and an address
// reaches here from a provider or from somebody typing one in. Refusing is not
// available at this point, so what is carried is the first line and nothing
// after it.
func sanitizedHeader(value string) string { return oneLine(value) }

func oneLine(value string) string {
	if i := strings.IndexAny(value, "\r\n"); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}
