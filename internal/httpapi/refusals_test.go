// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

// TestALostConnectionIsAFaultInEveryRefusalMapper passes each mapper a store
// error wrapping a failed dial, which carries the address the driver tried,
// and asks for a server error whose words name none of it.
func TestALostConnectionIsAFaultInEveryRefusalMapper(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	lost := fmt.Errorf("read what is open there: %w", &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 4, 7), Port: 5432},
		Err: errors.New("connection refused"),
	})
	for name, mapped := range map[string]error{
		"asked":              asked(quiet, lost),
		"refusedDecision":    refusedDecision(quiet, lost),
		"refusedNote":        refusedNote(quiet, lost),
		"declineDeclaration": declineDeclaration(quiet, lost),
		"vexRefused":         vexRefused(Ingest{Logger: quiet}, lost, "that could not be read"),
	} {
		var status huma.StatusError
		if !errors.As(mapped, &status) || status.GetStatus() != 500 {
			t.Errorf("%s answered %v, want a 500", name, mapped)
			continue
		}
		if strings.Contains(mapped.Error(), "10.0.4.7") {
			t.Errorf("%s published the address: %v", name, mapped)
		}
	}
}
