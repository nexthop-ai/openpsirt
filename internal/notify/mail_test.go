// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
)

// plainServer is an SMTP server that offers no STARTTLS and accepts whatever
// it is sent, recording each command and the message it was given.
type plainServer struct {
	addr string

	mu       sync.Mutex
	commands []string
	data     string
}

func servePlain(t *testing.T) *plainServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	s := &plainServer{addr: listener.Addr().String()}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.converse(conn)
		}
	}()
	return s
}

func (s *plainServer) converse(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	in := bufio.NewReader(conn)
	say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	say("220 plain.test ESMTP")
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.mu.Lock()
		s.commands = append(s.commands, line)
		s.mu.Unlock()
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO":
			// Offers authentication and no way to secure the connection.
			say("250-plain.test")
			say("250 AUTH PLAIN")
		case "AUTH":
			say("235 accepted")
		case "DATA":
			say("354 go ahead")
			var body strings.Builder
			for {
				part, err := in.ReadString('\n')
				if err != nil {
					return
				}
				if part == ".\r\n" {
					break
				}
				body.WriteString(part)
			}
			s.mu.Lock()
			s.data = body.String()
			s.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (s *plainServer) sent() ([]string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...), s.data
}

// A password is not sent over a connection nothing secured. A server that
// offers no STARTTLS is refused before any AUTH is written to it, where a
// username is configured; with none, the message is delivered in the clear,
// because there is nothing to give away.
//
// Verified by deleting the `!secured` refusal in Send: the credentials are
// then written to the server, which accepts them.
func TestAPasswordIsNeverSentWithoutSTARTTLS(t *testing.T) {
	server := servePlain(t)
	err := NewMail(server.addr, "psirt@example.test", "psirt", "hunter2").
		Send(t.Context(), "ana@example.test", Message{Subject: "s", Text: "t"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("sending with a password over an unsecured connection got %v", err)
	}
	commands, _ := server.sent()
	for _, command := range commands {
		if strings.HasPrefix(strings.ToUpper(command), "AUTH") {
			t.Errorf("credentials were written to a server that secured nothing: %q", command)
		}
	}

	open := servePlain(t)
	if err := NewMail(open.addr, "psirt@example.test", "", "").
		Send(t.Context(), "ana@example.test", Message{Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("sending with no credentials was refused: %v", err)
	}
	if _, data := open.sent(); !strings.HasPrefix(data, "From: psirt@example.test\r\n") {
		t.Errorf("the message delivered opens %q", data)
	}
}

// An address carrying a line break is cut at it, so a second header cannot be
// written through one. The subject is kept to one line as well.
//
// Verified by making sanitizedHeader return its value unchanged: the injected
// Bcc and Cc headers are then written.
func TestAnAddressCannotAddAHeader(t *testing.T) {
	rendered := string(headers("psirt@example.test\r\nBcc: evil@example.test",
		"ana@example.test\nCc: evil@example.test",
		Message{Subject: "Findings\r\nX-Injected: yes", Text: "body"}))
	head, _, _ := strings.Cut(rendered, "\r\n\r\n")
	// Split at either character, since a server reading a bare one as the end
	// of a line is what an injection relies on.
	lines := strings.FieldsFunc(head, func(r rune) bool { return r == '\r' || r == '\n' })
	for _, line := range lines {
		for _, forbidden := range []string{"Bcc:", "Cc:", "X-Injected:"} {
			if strings.HasPrefix(line, forbidden) {
				t.Errorf("a header was injected: %q", line)
			}
		}
	}
	for _, want := range []string{"From: psirt@example.test", "To: ana@example.test"} {
		found := false
		for _, line := range lines {
			found = found || line == want
		}
		if !found {
			t.Errorf("no header reads %q in %q", want, head)
		}
	}
}
