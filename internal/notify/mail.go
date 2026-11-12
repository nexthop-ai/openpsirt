// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// defaultMailTimeout bounds the whole conversation with a mail server where
// nobody has said otherwise.
const defaultMailTimeout = 30 * time.Second

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
	// Timeout bounds one message. The sweep's lease is sized from it, since
	// a lease has to cover a cycle of the work rather than an instant of it,
	// and what a cycle can cost is the batch times this.
	Timeout() time.Duration
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
	// roots is what the server's certificate is checked against once the
	// connection is secured. Nil is the system's.
	roots *x509.CertPool
	// plaintext accepts a server that offers no STARTTLS, for a password-less
	// relay on a network the operator accepts mail crossing in the clear.
	plaintext bool
}

// NewMail returns a channel over the SMTP server at addr, or nil where the
// deployment has not configured one.
//
// Nil rather than an error: not configuring mail is a choice an operator is
// entitled to make, and the tool works without it.
func NewMail(addr, from, username, password string, plaintext bool) *Mail {
	addr, from = strings.TrimSpace(addr), strings.TrimSpace(from)
	if addr == "" || from == "" {
		return nil
	}
	return &Mail{
		addr: addr, from: from,
		username: strings.TrimSpace(username), password: password,
		timeout: defaultMailTimeout, plaintext: plaintext,
	}
}

// Timeout bounds the whole conversation with the server.
func (m *Mail) Timeout() time.Duration { return m.timeout }

// Name is what this channel is called in a log line.
func (m *Mail) Name() string { return "mail" }

// Send carries one message to one address.
//
// Only over a connection STARTTLS secured, unless the operator accepted
// plaintext, and credentials never otherwise: a message names findings and
// people, and a password sent in the clear is a password given away. A
// connection whose STARTTLS was stripped on the way reads as a server offering
// none, so offering it is not left to the server.
func (m *Mail) Send(ctx context.Context, to string, message Message) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return refusal.New("no address to send to")
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
		if err := client.StartTLS(&tls.Config{ServerName: host, RootCAs: m.roots, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("secure the connection to the mail server: %w", err)
		}
		secured = true
	}
	if !secured && m.username != "" {
		return fmt.Errorf("%w, and a password sent in the clear is a password given away", ErrUnsecured)
	}
	if !secured && !m.plaintext {
		return fmt.Errorf("%w, and OPENPSIRT_MAIL_ALLOW_PLAINTEXT is not set to send mail across "+
			"the network in the clear", ErrUnsecured)
	}
	if m.username != "" {
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
	id, err := messageID(m.from)
	if err != nil {
		return err
	}
	if _, err := writer.Write(headers(m.from, to, time.Now().UTC(), id, message)); err != nil {
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
//
// Date and Message-ID are written here, since RFC 5322 requires the one and
// some receivers refuse a message without the other, and a relay that adds
// neither is a relay this has to work through. The body is UTF-8 sent as it
// is, which the encoding header says.
func headers(from, to string, at time.Time, id string, m Message) []byte {
	var out strings.Builder
	out.WriteString("From: " + sanitizedHeader(from) + "\r\n")
	out.WriteString("To: " + sanitizedHeader(to) + "\r\n")
	out.WriteString("Date: " + at.UTC().Format(time.RFC1123Z) + "\r\n")
	out.WriteString("Message-ID: " + id + "\r\n")
	out.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", oneLine(m.Subject)) + "\r\n")
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	out.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	out.WriteString("\r\n")
	out.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))
	return []byte(out.String())
}

// ErrUnsecured says the mail server offered no STARTTLS where one is required.
// It is this deployment's configuration, never the message, so a send refused
// this way leaves the message waiting for the configuration to change.
var ErrUnsecured = refusal.New("the mail server offered no STARTTLS")

// messageID is a new message's identifier: random, at the domain of the
// address it is sent as.
func messageID(from string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("name a message: %w", err)
	}
	domain := "openpsirt.invalid"
	if parsed, err := mail.ParseAddress(oneLine(from)); err == nil {
		if at := strings.LastIndex(parsed.Address, "@"); at >= 0 && at < len(parsed.Address)-1 {
			domain = parsed.Address[at+1:]
		}
	}
	return "<" + hex.EncodeToString(random[:]) + "@" + domain + ">", nil
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
