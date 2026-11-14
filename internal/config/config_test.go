// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// A variable carrying the prefix that names no setting is refused, naming it,
// since a misspelled switch would leave its default in force. The variables
// Kubernetes gives a pod for a Service whose name begins with the prefix are
// read as what they are.
func TestAVariableThatIsNotASettingIsRefused(t *testing.T) {
	for _, name := range []string{
		"OPENPSIRT_DB_REQUIRE_ENCRYPTON",
		"OPENPSIRT_PLAIN_HTTP_",
		"OPENPSIRT_",
		"OPENPSIRT_BASEURL",
	} {
		_, err := Load([]string{"OPENPSIRT_ADDR=:8080", name + "=true"})
		if err == nil || !strings.Contains(err.Error(), name+": not a setting") {
			t.Errorf("%s answered %v, want a refusal naming it", name, err)
		}
	}
	// A setting misspelled into the shape of a service link, with a value
	// no link has.
	for _, kv := range []string{
		"OPENPSIRT_MAIL_PORT=587",
		"OPENPSIRT_DATABASE_PORT=5432",
		"OPENPSIRT_PORT=8080",
		"OPENPSIRT_DATABASE_SERVICE_HOST=db.example.test",
		"OPENPSIRT_SERVICE_PORT=http",
		"OPENPSIRT_PORT_80_TCP_PROTO=http",
	} {
		name, _, _ := strings.Cut(kv, "=")
		_, err := Load([]string{kv})
		if err == nil || !strings.Contains(err.Error(), name+": not a setting") {
			t.Errorf("%s answered %v, want a refusal naming it", kv, err)
		}
	}
	_, err := Load([]string{"OPENPSIRT_TWO=1", "OPENPSIRT_ONE=1", "OPENPSIRT_TWO=2"})
	if err == nil || !strings.Contains(err.Error(), "OPENPSIRT_ONE, OPENPSIRT_TWO: not a setting") {
		t.Errorf("two answered %v, want a refusal naming each once, in order", err)
	}

	links := []string{
		"OPENPSIRT_SERVICE_HOST=10.0.0.1",
		"OPENPSIRT_SERVICE_PORT=8080",
		"OPENPSIRT_SERVICE_PORT_HTTP=8080",
		"OPENPSIRT_PORT=tcp://10.0.0.1:8080",
		"OPENPSIRT_PORT_8080_TCP=tcp://10.0.0.1:8080",
		"OPENPSIRT_PORT_8080_TCP_PROTO=tcp",
		"OPENPSIRT_PORT_8080_TCP_PORT=8080",
		"OPENPSIRT_PORT_8080_TCP_ADDR=10.0.0.1",
		"OPENPSIRT_POSTGRESQL_SERVICE_HOST=10.0.0.2",
		"OPENPSIRT_POSTGRESQL_PORT_5432_TCP_ADDR=10.0.0.2",
		"OPENPSIRT_POSTGRESQL_PORT_5432_TCP_PORT=5432",
		"OPENPSIRT_POSTGRESQL_PORT=tcp://[fd00::2]:5432",
		"OPENPSIRT_X_SERVICE_SERVICE_HOST=fd00::3",
		// Services named openpsirt-api-service and openpsirt-service, whose
		// names end in a link's suffix.
		"OPENPSIRT_API_SERVICE_PORT=tcp://10.0.0.5:8080",
		"OPENPSIRT_API_SERVICE_SERVICE_PORT=8080",
		"OPENPSIRT_SERVICE_PORT=tcp://10.0.0.6:8080",
		// A named port whose name ends in another suffix.
		"OPENPSIRT_SERVICE_PORT_HTTP_ADDR=8080",
		"OPENPSIRT_SERVICE_PORT_TCP_PROTO=8080",
		"OPENPSIRT_TEST_POSTGRES_URL=postgres://localhost/test",
		// The interface's development server's.
		"OPENPSIRT_DEV_USER=admin",
		// The upload client's, set in a job that runs both programs.
		"OPENPSIRT_URL=https://psirt.example.com", "OPENPSIRT_KEY=k",
		"PATH=/usr/bin",
	}
	if _, err := Load(links); err != nil {
		t.Errorf("Kubernetes service links were refused: %v", err)
	}
}

// Where a name is set twice the first is read, as the process reads it.
func TestTheFirstOfAVariableSetTwiceIsRead(t *testing.T) {
	c, err := Load([]string{"OPENPSIRT_ADDR=:1", "OPENPSIRT_ADDR=:2"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":1" {
		t.Errorf("read %q, want the first, :1", c.Addr)
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(os.Environ())
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
		// Empty, the CVE record snapshot is never found and nothing narrows.
		{"RECORDS_DIR", " "},
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
		// An empty query is a query: written back out, the "?" lands between
		// the directory and every name joined to it.
		{"DIRECTORY_URL", "https://psirt.example.test/csaf?"},
		// Swallowed, a list that cannot be read empties the exclusions, and
		// every internal host becomes somewhere a report can send a fetch.
		{"OUTBOUND_EXCLUDED", "10.0.0.0/33"},
		{"OUTBOUND_EXCLUDED", "not a host"},
		// Dropped, a mapping that cannot be read leaves the deployment
		// starting with no group mappings and nobody holding what one grants.
		{"GROUP_ROLES", "leads=owner"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(envPrefix+tc.key, tc.value)
			_, err := Load(os.Environ())
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
			cfg, err := Load(os.Environ())
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
			_, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if c.PatchBranches {
		t.Error("patch branch lookups are on in a deployment that never turned them on")
	}
}

func TestTheExcludedListIsReadUnderItsName(t *testing.T) {
	t.Setenv(envPrefix+"OUTBOUND_EXCLUDED", "corp.example.com")
	c, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
	if err != nil {
		t.Fatalf("a server with somebody to send as was refused: %v", err)
	}
	if c.MailServer == "" || c.MailFrom == "" {
		t.Errorf("read the server as %q sending as %q", c.MailServer, c.MailFrom)
	}
}

// Plain mail beside a username configures nothing: the username is sent only
// after STARTTLS, so a server without it is refused either way.
func TestPlainMailBesideAUsernameIsRefused(t *testing.T) {
	t.Setenv(envPrefix+"MAIL_SERVER", "relay.example.test:25")
	t.Setenv(envPrefix+"MAIL_FROM", "psirt@example.test")
	t.Setenv(envPrefix+"MAIL_ALLOW_PLAINTEXT", "true")
	if _, err := Load(os.Environ()); err != nil {
		t.Fatalf("plain mail with no username was refused: %v", err)
	}
	t.Setenv(envPrefix+"MAIL_USERNAME", "mailer")
	if _, err := Load(os.Environ()); err == nil ||
		!strings.Contains(err.Error(), "OPENPSIRT_MAIL_ALLOW_PLAINTEXT and OPENPSIRT_MAIL_USERNAME") {
		t.Errorf("plain mail beside a username was answered %v", err)
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
			c, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
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
	if _, err := Load(os.Environ()); err == nil {
		t.Fatal("a sign-in lasting a year was accepted at startup")
	} else if !strings.Contains(err.Error(), access.MaxSessionLifetime.String()) {
		t.Errorf("the refusal does not say the limit: %v", err)
	}

	// The ceiling itself, and the ordinary case, both start.
	for _, lifetime := range []string{access.MaxSessionLifetime.String(), "12h"} {
		t.Setenv("OPENPSIRT_SESSION_LIFETIME", lifetime)
		if _, err := Load(os.Environ()); err != nil {
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
		_, err := Load(os.Environ())
		if (err != nil) != c.refused {
			t.Errorf("%s (%q): refused = %v, want %v (%v)",
				c.what, c.base, err != nil, c.refused, err)
		}
		if err != nil && !strings.Contains(err.Error(), "OPENPSIRT_BASE_URL") {
			t.Errorf("%s (%q): the refusal does not name the variable: %v", c.what, c.base, err)
		}
	}
}

// An "@" in a published address's path reads as a password cut short, so its
// refusal says how to write one that is not.
func TestAnAtSignInAnAddressPathIsRefusedSayingHowToWriteIt(t *testing.T) {
	t.Setenv(envPrefix+"DIRECTORY_URL", "https://cdn.example.test/gh/org/advisories@main/csaf")
	_, err := Load(os.Environ())
	if err == nil || !strings.Contains(err.Error(), "%40") || !strings.Contains(err.Error(), envPrefix+"DIRECTORY_URL") {
		t.Errorf("answered %v, want a refusal naming the setting and %%40", err)
	}
	// A fragment holding no "@" is refused as a fragment.
	t.Setenv(envPrefix+"DIRECTORY_URL", "https://cdn.example.test/csaf#top")
	_, err = Load(os.Environ())
	if err == nil || strings.Contains(err.Error(), "%40") || !strings.Contains(err.Error(), "fragment") {
		t.Errorf("answered %v, want a refusal naming the fragment", err)
	}
}

// A refusal names the address with anything that may be a password masked,
// since a refusal is logged. That holds on every arm, including a value the
// parser reads as a scheme and an opaque rest, and one it cannot parse at all.
func TestARefusedAddressDoesNotRepeatItsPassword(t *testing.T) {
	for _, key := range []string{"BASE_URL", "DIRECTORY_URL", "ZULIP_SITE"} {
		for _, value := range []string{
			"https://psirt.example.test/?token=hunter2",
			"https://psirt.example.test/#hunter2",
			"https://user:hunter2%zz@psirt.example.test/",
			"https://user:hunter2@psirt.example.test/",
			"admin:hunter2@psirt.example.test",
			"ftp://user:hunter2@psirt.example.test/",
			"https://user:hunter2@/",
			"https://user:hunter2@psirt.example.test/below",
			"https://user:hunter2@psirt.example.test:bad/",
			"http://user:hunter2@psirt.example.test/",
			"https://hunter2@psirt.example.test/",
			// A password holding an unescaped "/" parses with its start as
			// the host and the rest in the path.
			"https://user:12/hunter2@psirt.example.test/csaf",
		} {
			t.Run(key+" "+value, func(t *testing.T) {
				t.Setenv(envPrefix+key, value)
				if key == "ZULIP_SITE" {
					t.Setenv(envPrefix+"ZULIP_EMAIL", "bot@chat.example.test")
					t.Setenv(envPrefix+"ZULIP_KEY", "k")
				}
				_, err := Load(os.Environ())
				if err == nil {
					t.Fatal("an address carrying credentials was accepted")
				}
				if !strings.Contains(err.Error(), envPrefix+key) {
					t.Errorf("refused for something else: %v", err)
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
	c, err := Load(os.Environ())
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
			_, err := Load(os.Environ())
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
	c, err := Load(os.Environ())
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
		"https://user:pass@chat.example.test",
		// Every API path is appended to the site, so anything after the host
		// lands in front of each one.
		"https://chat.example.test/?x", "https://chat.example.test/?",
		"https://chat.example.test/#f", "https://chat.example.test/zulip"} {
		t.Setenv("OPENPSIRT_ZULIP_SITE", site)
		if _, err := Load(os.Environ()); err == nil || !strings.Contains(err.Error(), "OPENPSIRT_ZULIP_SITE") {
			t.Errorf("a Zulip server at %q answered %v, want it refused by name", site, err)
		}
	}
	t.Setenv("OPENPSIRT_ZULIP_SITE", "https://chat.example.test")
	if _, err := Load(os.Environ()); err != nil {
		t.Errorf("a whole Zulip configuration was refused: %v", err)
	}
}

// The published directory is served to anybody, so it is never the attachment
// store, a folder holding it, or a folder inside it.
func TestThePublishedDirectoryIsNeverTheAttachmentStore(t *testing.T) {
	root := t.TempDir()
	// served/attachments, written as linked, and private/csaf, written
	// through link-to-private. Neither link's own name shares a folder with
	// what it points at.
	for _, dir := range []string{"served/attachments", "private"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "served"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "private"), filepath.Join(root, "link-to-private")); err != nil {
		t.Fatal(err)
	}
	// A link to a folder not made yet, inside private.
	if err := os.Symlink(filepath.Join(root, "private", "pub"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	// A relative link to a folder not made yet, inside private, reached
	// through a link one folder shallower than where it sits.
	if err := os.Symlink(filepath.Join(root, "served", "attachments"), filepath.Join(root, "shallow")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "private", "rel"), filepath.Join(root, "served", "attachments", "rel")); err != nil {
		t.Fatal(err)
	}
	resolves := map[string][]string{
		"minio":                                {"10.0.0.5"},
		"minio.storage.svc.cluster.local":      {"10.0.0.5"},
		"localhost":                            {"::1", "127.0.0.1"},
		"ec2-54-1-2-3.compute-1.amazonaws.com": {"54.1.2.3"},
		"minio.corp.example":                   {"54.1.2.3"},
		"minio-1.elb.us-east-1.amazonaws.com":  {"54.9.9.9"},
	}
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if found, ok := resolves[host]; ok {
			return slices.Clone(found), nil
		}
		if host == "flaky" {
			return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { lookupHost = net.DefaultResolver.LookupHost })
	for _, c := range []struct {
		what    string
		set     map[string]string
		refused string
	}{
		{"one bucket", map[string]string{"DIRECTORY_BUCKET": "psirt", "ATTACHMENT_BUCKET": "PSIRT"}, "DIRECTORY_BUCKET"},
		// A short name and a cluster name, or a name and its address, reach
		// one server.
		{"one bucket on two names of one server", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "http://minio:9000",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "http://minio.storage.svc.cluster.local:9000",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on a name whose lookup failed", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "http://flaky:9000",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "http://minio:9000",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on a name and its address", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "http://127.0.0.1:9000",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "http://localhost:9000",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on one endpoint", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://minio.example.test/",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://MINIO.example.test",
		}, "DIRECTORY_BUCKET"},
		// Amazon's bucket names are global, so its default endpoint and
		// every regional one reach one bucket of a name.
		{"one bucket on the default and a regional endpoint", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.eu-west-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on one path of one host", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.example.test/tenant-a/",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://S3.example.test/tenant-a",
		}, "DIRECTORY_BUCKET"},
		// An unset endpoint is the same as any endpoint.
		{"one bucket on the default endpoint and one in GovCloud", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_REGION": "us-gov-west-1",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_REGION": "us-gov-west-1",
			"ATTACHMENT_ENDPOINT": "https://s3.us-gov-west-1.amazonaws.com",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on the default endpoint and one in China", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.cn-north-1.amazonaws.com.cn",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_REGION": "cn-north-1",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on two endpoints in GovCloud", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.us-gov-west-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3-fips.us-gov-east-1.amazonaws.com",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on two endpoints in China", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.cn-north-1.amazonaws.com.cn",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.cn-northwest-1.amazonaws.com.cn",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on two regional endpoints", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.us-east-1.amazonaws.com",
		}, "DIRECTORY_BUCKET"},
		// The store takes credentials out of its endpoint before using it.
		{"one bucket on one endpoint, one with credentials", map[string]string{ //nolint:gosec // G101: a made-up credential the store strips
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://minio.example.test:9000",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://key:secret@minio.example.test:9000",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on one endpoint, one naming its default port", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://minio.example.test:443/",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://minio.example.test",
		}, "DIRECTORY_BUCKET"},
		// An unset endpoint is whatever the SDK resolves, and
		// AWS_ENDPOINT_URL_S3 can point it anywhere.
		{"one bucket on the default endpoint and another store", map[string]string{
			"DIRECTORY_BUCKET":  "psirt",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://minio.example.test:9000",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on an endpoint that does not parse", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://minio.example.test:x/",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://two.example.test",
		}, "DIRECTORY_BUCKET"},
		{"one folder", map[string]string{"DIRECTORY_DIR": root + "/a", "ATTACHMENT_DIR": root + "/a/"}, "DIRECTORY_DIR"},
		{"the attachments inside the directory through a link", map[string]string{
			"DIRECTORY_DIR": root + "/linked", "ATTACHMENT_DIR": root + "/served/attachments",
		}, "DIRECTORY_DIR"},
		{"the directory inside the attachments through a link to a folder not made yet", map[string]string{
			"DIRECTORY_DIR": root + "/dangling", "ATTACHMENT_DIR": root + "/private",
		}, "DIRECTORY_DIR"},
		{"the directory inside the attachments through a relative link to a folder not made yet", map[string]string{
			"DIRECTORY_DIR": root + "/shallow/rel", "ATTACHMENT_DIR": root + "/private",
		}, "DIRECTORY_DIR"},
		{"the directory inside the attachments through a link", map[string]string{
			"DIRECTORY_DIR": root + "/link-to-private/csaf", "ATTACHMENT_DIR": root + "/private",
		}, "DIRECTORY_DIR"},
		{"the attachments inside the directory", map[string]string{
			"DIRECTORY_DIR": root, "ATTACHMENT_DIR": root + "/attachments",
		}, "DIRECTORY_DIR"},
		{"the directory inside the attachments", map[string]string{
			"DIRECTORY_DIR": root + "/files/csaf", "ATTACHMENT_DIR": root + "/files",
		}, "DIRECTORY_DIR"},

		// Only an S3 endpoint is Amazon's one service; any other Amazon host
		// is a server like any other.
		{"one bucket on an Amazon EC2 name and another name of that server", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "http://ec2-54-1-2-3.compute-1.amazonaws.com:9000",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "http://minio.corp.example:9000",
		}, "DIRECTORY_BUCKET"},

		{"two buckets", map[string]string{"DIRECTORY_BUCKET": "csaf", "ATTACHMENT_BUCKET": "psirt"}, ""},
		{"one name on two stores", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://one.example.test",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://two.example.test",
		}, ""},
		{"one name on two ports of one host", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://minio.example.test:9000",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://minio.example.test:9001",
		}, ""},
		{"one name on two paths of one host", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.example.test/tenant-a",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.example.test/tenant-b/",
		}, ""},
		// The China partition is a namespace of its own.
		// A bucket's own name in the host says nothing of the partition.
		{"one bucket named like GovCloud on two commercial endpoints", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://corp-us-gov-mirror.s3.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.amazonaws.com",
		}, "DIRECTORY_BUCKET"},
		{"one bucket on two GovCloud spellings", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3-fips-us-gov-west-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://psirt.s3.us-gov-east-1.amazonaws.com",
		}, "DIRECTORY_BUCKET"},
		{"one name on Amazon and on Amazon GovCloud's dashed address", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3-us-gov-west-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.us-east-1.amazonaws.com",
		}, ""},
		{"one name on Amazon and on Amazon GovCloud", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.us-gov-west-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.us-east-1.amazonaws.com",
		}, ""},
		{"one name on Amazon and on Amazon in China", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3.cn-north-1.amazonaws.com.cn",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.amazonaws.com",
		}, ""},
		{"one name on Amazon S3 and on a store behind an Amazon load balancer", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://minio-1.elb.us-east-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://s3.us-east-1.amazonaws.com",
		}, ""},
		{"one name on Amazon S3 and on Amazon S3's external endpoint", map[string]string{
			"DIRECTORY_BUCKET": "psirt", "DIRECTORY_ENDPOINT": "https://s3-external-1.amazonaws.com",
			"ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_ENDPOINT": "https://psirt.s3.dualstack.us-east-1.amazonaws.com",
		}, "DIRECTORY_BUCKET"},
		{"sibling folders", map[string]string{"DIRECTORY_DIR": root + "/csaf", "ATTACHMENT_DIR": root + "/csaf-private"}, ""},
		{"a bucket beside a folder", map[string]string{"DIRECTORY_DIR": root, "ATTACHMENT_BUCKET": "psirt", "ATTACHMENT_DIR": root}, ""},
	} {
		t.Run(c.what, func(t *testing.T) {
			t.Setenv(envPrefix+"DIRECTORY_URL", "https://psirt.example.test/csaf")
			for key, value := range c.set {
				t.Setenv(envPrefix+key, value)
			}
			_, err := Load(os.Environ())
			if c.refused == "" {
				if err != nil {
					t.Errorf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), envPrefix+c.refused) {
				t.Errorf("answered %v, want a refusal naming %s", err, envPrefix+c.refused)
			}
		})
	}
}
