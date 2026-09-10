package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
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
