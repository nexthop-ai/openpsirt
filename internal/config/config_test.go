// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestLoadDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load with nothing set: %v", err)
	}
	if c.Addr == "" || c.LogFormat == "" || c.ShutdownGrace == 0 {
		t.Fatalf("a default is missing: %+v", c)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	// A value that is set and cannot be read stops the process, with the
	// variable named. A fallback here is a setting that silently does
	// nothing, or the opposite of what it says.
	for _, tc := range []struct{ key, value string }{
		{"LOG_LEVEL", "chatty"},
		{"LOG_FORMAT", "yaml"},
		{"ADDR", "  "},
		{"PLAIN_HTTP", "yes"},
		{"AUTO_MIGRATE", "no"},
		{"SHUTDOWN_GRACE", "soon"},
		{"SHUTDOWN_GRACE", "0"},
		{"SHUTDOWN_GRACE", "-5s"},
		{"DB_IDLE_TIMEOUT", "1 minute"},
		{"SESSION_LIFETIME", "12"},
		{"DB_MAX_OPEN", "many"},
		{"DB_MAX_OPEN", "0"},
		// The trusted-header pair. A half-configuration is the dangerous state: a header named with
		// nothing to trust it from is either a mistake or the first half of
		// one, and sources configured with no header named reads nothing from
		// them.
		{"TRUSTED_HEADER", "X-User"},
		{"TRUSTED_SOURCES", "not-an-address"},
		// The mail pair, on the same rule. A server with nobody to send as is
		// not a configuration, it is half of one — and half of one answered
		// as "no mail configured", which is a choice an operator is entitled
		// to make and is indistinguishable from the mistake. Embargo mail is
		// what a coordinated disclosure runs on, and it goes silently off.
		{"MAIL_SERVER", "smtp.example.test:587"},
		{"MAIL_FROM", "psirt@example.test"},
		// A Zulip bot is its server, its address and its key together, and
		// any one alone reaches nothing.
		{"ZULIP_SITE", "https://chat.example.test"},
		{"ZULIP_KEY", "k"},
		// The standard permits exactly six words here and the value reaches
		// the document verbatim, so a typo produces advisories that fail
		// validation wherever anybody takes them — the one use a generated
		// advisory has.
		{"ADVISORY_PREFIX", "nexthop"},
		{"ADVISORY_PREFIX", "NEXT HOP"},
		{"ADVISORY_PREFIX", "1NEXTHOP"},
		{"ADVISORY_PREFIX", "NEXTHOPNEXTHOPNEXTHOPNEXTHOP"},
		{"PUBLISHER_CATEGORY", "vendo"},
		{"PUBLISHER_CATEGORY", "Vendor"},
		{"PUBLISHER_CATEGORY", ""},
		// The address published documents state about themselves. It reaches
		// a document and the provider description verbatim, and a reader
		// outside this deployment is the only one who ever notices it is
		// wrong — so a relative one, or one over a transport that does not
		// authenticate the server, is refused here.
		{"DIRECTORY_URL", "http://psirt.example.test/csaf"},
		{"DIRECTORY_URL", "/csaf"},
		{"DIRECTORY_URL", "psirt.example.test/csaf"},
		{"DIRECTORY_URL", "https://"},
		// A name is joined to the end of the address, so anything after its
		// path lands in the middle of every document's own address, and a
		// password in it is published in every one of them.
		{"DIRECTORY_URL", "https://u:p@psirt.example.test/csaf"},
		{"DIRECTORY_URL", "https://psirt.example.test/csaf?x=1"},
		{"DIRECTORY_URL", "https://psirt.example.test/csaf#f"},
		// Swallowed, a list that cannot be read empties the exclusions, and
		// every internal host becomes somewhere a report can send a fetch.
		{"OUTBOUND_EXCLUDED", "10.0.0.0/33"},
		{"OUTBOUND_EXCLUDED", "not a host"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(envPrefix+tc.key, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", tc.key, tc.value)
			}
			if !strings.Contains(err.Error(), envPrefix+tc.key) {
				t.Errorf("the refusal does not name the variable: %v", err)
			}
		})
	}
}

// The address is given one trailing slash, so that everything below joins a
// name to it rather than parsing it again.
//
// Both ways round: an operator who wrote the slash and one who did not
// configured the same directory, and a document that stated the address two
// ways would cite files the directory does not serve.
func TestThePublishedAddressIsNormalizedWhicheverWayItWasWritten(t *testing.T) {
	for _, given := range []string{
		"https://psirt.example.test/.well-known/csaf",
		"https://psirt.example.test/.well-known/csaf/",
	} {
		t.Run(given, func(t *testing.T) {
			t.Setenv(envPrefix+"DIRECTORY_URL", given)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			const want = "https://psirt.example.test/.well-known/csaf/"
			if cfg.DirectoryURL != want {
				t.Errorf("read as %q, want %q", cfg.DirectoryURL, want)
			}
		})
	}
}

func TestATrustedHeaderHonoredFromAnywhereIsRefused(t *testing.T) {
	// The one setting that is supposed to be the guard, naming every address.
	// It is the same reach as trusting the header from anywhere, and halting
	// on the empty case while accepting this one is a guard that catches only
	// the honest mistake.
	//
	// This is the only production caller of the check, and without it the
	// trusted identity header is honored from any address that can reach the
	// process.
	for _, sources := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8,0.0.0.0/0"} {
		t.Run(sources, func(t *testing.T) {
			t.Setenv(envPrefix+"TRUSTED_HEADER", "X-User")
			t.Setenv(envPrefix+"TRUSTED_SOURCES", sources)
			_, err := Load()
			if err == nil {
				t.Fatalf("TRUSTED_SOURCES=%q was accepted, so the header is honored "+
					"from every address", sources)
			}
			if !strings.Contains(err.Error(), envPrefix+"TRUSTED_HEADER") {
				t.Errorf("the refusal does not name the variable: %v", err)
			}
		})
	}
}

// The patch branch lookups reach out to hosts a report chooses, so a
// deployment that says nothing about them has them off.
func TestPatchBranchesAreOffUnlessTheDeploymentTurnsThemOn(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.PatchBranches {
		t.Error("patch branch lookups are on in a deployment that never turned them on")
	}
}

func TestTheExcludedListUnderItsOldNameIsRefusedRatherThanIgnored(t *testing.T) {
	// Ignored, a deployment that set the old name fetches from everything it
	// meant to keep out.
	t.Setenv(envPrefix+"PATCH_EXCLUDED", "corp.example.com")
	_, err := Load()
	if err == nil {
		t.Fatal("the old name was accepted and nothing it lists is excluded")
	}
	if !strings.Contains(err.Error(), envPrefix+"OUTBOUND_EXCLUDED") {
		t.Errorf("the refusal does not name the new variable: %v", err)
	}
}

func TestTheExcludedListIsReadUnderItsName(t *testing.T) {
	t.Setenv(envPrefix+"OUTBOUND_EXCLUDED", "corp.example.com")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.OutboundExcluded.Host("mirror.corp.example.com") {
		t.Error("a host under an excluded name is not excluded")
	}
}

func TestATrustedHeaderAndTheSourcesItIsReadFromAreAcceptedTogether(t *testing.T) {
	// The other side, so the refusals above cannot be satisfied by refusing
	// the pair outright.
	t.Setenv(envPrefix+"TRUSTED_HEADER", "X-User")
	t.Setenv(envPrefix+"TRUSTED_SOURCES", "10.0.0.0/8,192.168.0.0/16")
	c, err := Load()
	if err != nil {
		t.Fatalf("a header with the networks it is read from was refused: %v", err)
	}
	if c.TrustedHeader != "X-User" || len(c.TrustedSources) != 2 {
		t.Errorf("read the header as %q from %v", c.TrustedHeader, c.TrustedSources)
	}
}

func TestAMailServerAndWhoItSendsAsAreAcceptedTogether(t *testing.T) {
	// The other side, so the refusals above cannot be satisfied by refusing
	// the pair outright — and so that configuring neither stays the ordinary
	// case it is.
	t.Setenv(envPrefix+"MAIL_SERVER", "smtp.example.test:587")
	t.Setenv(envPrefix+"MAIL_FROM", "psirt@example.test")
	c, err := Load()
	if err != nil {
		t.Fatalf("a server with somebody to send as was refused: %v", err)
	}
	if c.MailServer == "" || c.MailFrom == "" {
		t.Errorf("read the server as %q sending as %q", c.MailServer, c.MailFrom)
	}
}

func TestASwitchMeansWhatItSays(t *testing.T) {
	// Read as "set at all", "PLAIN_HTTP=false" turns plain HTTP on; read as
	// "anything but the word false", "AUTO_MIGRATE=0" still migrates.
	for _, tc := range []struct {
		key   string
		value string
		want  bool
		field func(Config) bool
	}{
		{"PLAIN_HTTP", "false", false, func(c Config) bool { return c.PlainHTTP }},
		{"PLAIN_HTTP", "0", false, func(c Config) bool { return c.PlainHTTP }},
		{"PLAIN_HTTP", "true", true, func(c Config) bool { return c.PlainHTTP }},
		{"PLAIN_HTTP", "1", true, func(c Config) bool { return c.PlainHTTP }},
		{"AUTO_MIGRATE", "0", false, func(c Config) bool { return c.AutoMigrate }},
		{"AUTO_MIGRATE", "False", false, func(c Config) bool { return c.AutoMigrate }},
		{"AUTO_MIGRATE", "1", true, func(c Config) bool { return c.AutoMigrate }},
		{"PATCH_BRANCHES", "true", true, func(c Config) bool { return c.PatchBranches }},
		{"PATCH_BRANCHES", "false", false, func(c Config) bool { return c.PatchBranches }},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(envPrefix+tc.key, tc.value)
			c, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := tc.field(c); got != tc.want {
				t.Errorf("%s=%q read as %v", tc.key, tc.value, got)
			}
		})
	}
}

func TestADurationIsReadAsWritten(t *testing.T) {
	t.Setenv(envPrefix+"SHUTDOWN_GRACE", "45s")
	t.Setenv(envPrefix+"DB_MAX_OPEN", "7")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ShutdownGrace != 45*time.Second {
		t.Errorf("ShutdownGrace = %v, want 45s", c.ShutdownGrace)
	}
	if c.DBMaxOpen != 7 {
		t.Errorf("DBMaxOpen = %d, want 7", c.DBMaxOpen)
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv(envPrefix+"ADDR", "127.0.0.1:9999")
	t.Setenv(envPrefix+"LOG_LEVEL", "debug")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Addr != "127.0.0.1:9999" {
		t.Errorf("Addr = %q", c.Addr)
	}
	if c.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v", c.LogLevel)
	}
}

func TestAutoMigrateIsOnByDefault(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.AutoMigrate {
		t.Error("auto-migration should be on by default")
	}
}

func TestASignInLifetimeOverTheCeilingIsRefusedAtStartup(t *testing.T) {
	// Enforced where a session is started and nowhere on the way in, a
	// deployment following the documented configuration starts cleanly and
	// then fails every browser sign-in with a fault — and the way back needs
	// an administrator's key, because nobody can sign in.
	t.Setenv("OPENPSIRT_DATABASE_URL", "sqlite://test.db")
	t.Setenv("OPENPSIRT_SESSION_LIFETIME", "8760h")
	if _, err := Load(); err == nil {
		t.Fatal("a sign-in lasting a year was accepted at startup")
	} else if !strings.Contains(err.Error(), access.MaxSessionLifetime.String()) {
		t.Errorf("the refusal does not say the limit: %v", err)
	}

	// The ceiling itself, and the ordinary case, both start.
	for _, lifetime := range []string{access.MaxSessionLifetime.String(), "12h"} {
		t.Setenv("OPENPSIRT_SESSION_LIFETIME", lifetime)
		if _, err := Load(); err != nil {
			t.Errorf("a lifetime of %s was refused: %v", lifetime, err)
		}
	}
}

func TestTheDeploymentsOwnAddressHasToBeOne(t *testing.T) {
	// A string setting with a required shape that nothing parses fails
	// silently exactly where it matters: `psirt.example.com` — the form the
	// value takes in a DNS record or an Ingress host field — parses, puts the
	// whole string in Path and leaves Host empty. The same-origin check then
	// falls through to origins derived from the request's own Host header, so
	// the guard echoes what the request said while the operator believes the
	// origin is pinned.
	for _, c := range []struct {
		what    string
		base    string
		refused bool
	}{
		{"nothing at all, which is how a deployment with no provider runs", "", false},
		{"an address", "https://psirt.example.com", false},
		{"one without encryption, for a deployment behind something", "http://psirt.internal", false},
		{"one with a port", "https://psirt.example.com:8443", false},
		{"one with a trailing slash", "https://psirt.example.com/", false},

		{"a bare host, which is the way this goes wrong", "psirt.example.com", true},
		{"a host with a port and no scheme", "psirt.example.com:8443", true},
		{"a scheme a browser does not speak", "ftp://psirt.example.com", true},
		{"a scheme and no host", "https://", true},
		{"a path below the address", "https://psirt.example.com/psirt", true},
		{"something that is not an address", "https://%zz", true},
		// Every sign-in callback and notification link appends a path to the
		// address, so anything after it lands in the middle of each one.
		{"a query", "https://psirt.example.com/?x", true},
		{"an empty query", "https://psirt.example.com/?", true},
		{"a fragment", "https://psirt.example.com/#top", true},
		{"credentials", "https://user:pw@psirt.example.com", true},
	} {
		t.Setenv("OPENPSIRT_DATABASE_URL", "sqlite://test.db")
		t.Setenv("OPENPSIRT_BASE_URL", c.base)
		_, err := Load()
		if (err != nil) != c.refused {
			t.Errorf("%s (%q): refused = %v, want %v (%v)",
				c.what, c.base, err != nil, c.refused, err)
		}
		if err != nil && !strings.Contains(err.Error(), "OPENPSIRT_BASE_URL") {
			t.Errorf("%s (%q): the refusal does not name the variable: %v", c.what, c.base, err)
		}
	}
}

// A refusal names the address with anything that may be a password masked,
// since a refusal is logged. That holds on every arm, including a value the
// parser reads as a scheme and an opaque rest, and one it cannot parse at all.
func TestARefusedAddressDoesNotRepeatItsPassword(t *testing.T) {
	for _, key := range []string{"BASE_URL", "DIRECTORY_URL"} {
		for _, value := range []string{
			"https://user:hunter2@psirt.example.test/",
			"admin:hunter2@psirt.example.test",
			"ftp://user:hunter2@psirt.example.test/",
			"https://user:hunter2@/",
			"https://user:hunter2@psirt.example.test/below",
			"https://user:hunter2@psirt.example.test:bad/",
			"http://user:hunter2@psirt.example.test/",
		} {
			t.Run(key+" "+value, func(t *testing.T) {
				t.Setenv(envPrefix+key, value)
				_, err := Load()
				if err == nil {
					t.Fatal("an address carrying credentials was accepted")
				}
				if strings.Contains(err.Error(), "hunter2") {
					t.Errorf("the refusal repeats the password: %v", err)
				}
			})
		}
	}
}

// A value that is only whitespace, which is what a template renders for a
// blank field, is no address at all rather than one made of spaces.
func TestABlankDirectoryAddressIsNoAddress(t *testing.T) {
	t.Setenv(envPrefix+"DIRECTORY_URL", "   ")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DirectoryURL != "" {
		t.Errorf("read as %q, want no address", c.DirectoryURL)
	}
}

// A directory store with no address it is served from writes files whose every
// address is a name with nothing in front of it.
func TestADirectoryStoreWithNoAddressIsRefused(t *testing.T) {
	for _, key := range []string{"DIRECTORY_DIR", "DIRECTORY_BUCKET"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(envPrefix+key, "/tmp/csaf")
			t.Setenv(envPrefix+"DIRECTORY_URL", "  ")
			_, err := Load()
			if err == nil {
				t.Fatalf("%s with no address was accepted", key)
			}
			if !strings.Contains(err.Error(), envPrefix+"DIRECTORY_URL") {
				t.Errorf("the refusal does not name the address it wants: %v", err)
			}
		})
	}
}

// The names that are never sent to a public index. Read, and read without the
// empty entries a template leaves: an empty name matches everything.
func TestTheInternalNamesAreReadAsAList(t *testing.T) {
	t.Setenv(envPrefix+"UPSTREAM_INTERNAL", " a, ,b,")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.UpstreamInternal, "|") != "a|b" {
		t.Errorf("read as %q, want [a b]", c.UpstreamInternal)
	}
}

func TestAZulipServerIsReachedOverHTTPSAlone(t *testing.T) {
	// The bot's key goes with every request, so a server over plain http is
	// refused rather than handed it.
	t.Setenv("OPENPSIRT_ZULIP_EMAIL", "bot@chat.example.test")
	t.Setenv("OPENPSIRT_ZULIP_KEY", "k")
	for _, site := range []string{"http://chat.example.test", "chat.example.test",
		"https://user:pass@chat.example.test"} {
		t.Setenv("OPENPSIRT_ZULIP_SITE", site)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "OPENPSIRT_ZULIP_SITE") {
			t.Errorf("a Zulip server at %q answered %v, want it refused by name", site, err)
		}
	}
	t.Setenv("OPENPSIRT_ZULIP_SITE", "https://chat.example.test")
	if _, err := Load(); err != nil {
		t.Errorf("a whole Zulip configuration was refused: %v", err)
	}
}
