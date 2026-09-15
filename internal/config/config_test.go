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
		// The trusted-header pair, which this table covered neither half of.
		// A half-configuration is the dangerous state: a header named with
		// nothing to trust it from is either a mistake or the first half of
		// one, and sources configured with no header named reads nothing from
		// them.
		{"TRUSTED_HEADER", "X-User"},
		{"TRUSTED_SOURCES", "not-an-address"},
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

func TestATrustedHeaderHonoredFromAnywhereIsRefused(t *testing.T) {
	// The one setting that is supposed to be the guard, naming every address.
	// It is the same reach as trusting the header from anywhere, and halting
	// on the empty case while accepting this one is a guard that catches only
	// the honest mistake.
	//
	// Nothing in the tree executed this. It is the only production caller of
	// the check at all, three lines, and with them gone the trusted identity
	// header is honored from any address that can reach the process.
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

func TestASwitchMeansWhatItSays(t *testing.T) {
	// "PLAIN_HTTP=false" used to turn plain HTTP on, because any value at all
	// did, and "AUTO_MIGRATE=0" still migrated because only "false" did not.
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

func TestAutoMigrateIsOnUnlessTurnedOff(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.AutoMigrate {
		t.Error("auto-migration should be on by default")
	}
	t.Setenv(envPrefix+"AUTO_MIGRATE", "false")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AutoMigrate {
		t.Error("auto-migration should be off when set to false")
	}
}

func TestASignInLifetimeOverTheCeilingIsRefusedAtStartup(t *testing.T) {
	// The ceiling was enforced where a session is started and nowhere on the
	// way in, so a deployment following the documented configuration started
	// cleanly and then failed every browser sign-in with a fault — and the way
	// back needed an administrator's key, because nobody could sign in.
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
