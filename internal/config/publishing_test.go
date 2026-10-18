// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// keyPassphrase is what lockedKey is locked with.
const keyPassphrase = "a passphrase"

// The two keys a test configures, made as the package loads rather than
// committed: a private key in the tree is what the secret scan exists to
// refuse, whoever it belongs to.
var plainKey, lockedKey = testKeys()

// testKeys is one signing key, armored as it stands and locked with
// keyPassphrase.
func testKeys() (plain, locked string) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("Example PSIRT", "", "psirt@example.test", cfg)
	if err != nil {
		panic(err)
	}
	write := func(serialize func(w interface{ Write([]byte) (int, error) }) error) string {
		var out strings.Builder
		w, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
		if err != nil {
			panic(err)
		}
		if err := serialize(w); err != nil {
			panic(err)
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
		return out.String()
	}
	plain = write(func(w interface{ Write([]byte) (int, error) }) error {
		return entity.SerializePrivate(w, cfg)
	})
	if err := entity.EncryptPrivateKeys([]byte(keyPassphrase), cfg); err != nil {
		panic(err)
	}
	locked = write(func(w interface{ Write([]byte) (int, error) }) error {
		return entity.SerializePrivateWithoutSigning(w, cfg)
	})
	return plain, locked
}

// publishingWith is a deployment that publishes, with the settings given on
// top of what publishing needs.
func publishingWith(extra map[string]string) map[string]string {
	given := map[string]string{
		"PUBLISH": "true", "BASE_URL": "https://psirt.example.test",
		"PUBLISHER_NAME": "Example", "PUBLISHER_NAMESPACE": "https://example.test",
	}
	for key, value := range extra {
		given[key] = value
	}
	return given
}

// A deployment that publishes starts with what publishing needs, and with a
// key that reads.
func TestPublishingStartsWithWhatItNeeds(t *testing.T) {
	for name, given := range map[string]map[string]string{
		"unsigned":                      publishingWith(nil),
		"signed":                        publishingWith(map[string]string{"PUBLISH_KEY": plainKey}),
		"signed, locked":                publishingWith(map[string]string{"PUBLISH_KEY": lockedKey, "PUBLISH_KEY_PASSPHRASE": keyPassphrase}),
		"a rate":                        publishingWith(map[string]string{"PUBLISH_RATE": "30"}),
		"trusted proxies and no header": publishingWith(map[string]string{"TRUSTED_SOURCES": "10.0.0.0/8"}),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := load(given)
			if err != nil {
				t.Fatal(err)
			}
			if !c.Publish {
				t.Error("publishing is off")
			}
		})
	}
	c, err := load(publishingWith(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublishRate != DefaultPublishRate {
		t.Errorf("the rate is %d where nothing set one, want %d", c.PublishRate, DefaultPublishRate)
	}
}

// Publishing is refused without what it needs, and a publishing setting is
// refused where publishing is off, naming the setting.
func TestPublishingIsRefusedWithoutWhatItNeeds(t *testing.T) {
	for name, tc := range map[string]struct {
		given map[string]string
		names string
	}{
		"no publisher": {
			map[string]string{"PUBLISH": "true", "BASE_URL": "https://psirt.example.test"},
			"OPENPSIRT_PUBLISHER_NAME",
		},
		"no address": {
			map[string]string{"PUBLISH": "true", "PUBLISHER_NAME": "Example",
				"PUBLISHER_NAMESPACE": "https://example.test"},
			"OPENPSIRT_BASE_URL",
		},
		"an address in the clear": {
			publishingWith(map[string]string{"BASE_URL": "http://psirt.example.test"}),
			"OPENPSIRT_BASE_URL",
		},
		"a key that is not one": {
			publishingWith(map[string]string{"PUBLISH_KEY": "not a key"}),
			"OPENPSIRT_PUBLISH_KEY",
		},
		"a locked key with no passphrase": {
			publishingWith(map[string]string{"PUBLISH_KEY": lockedKey}),
			"OPENPSIRT_PUBLISH_KEY",
		},
		"a locked key with the wrong passphrase": {
			publishingWith(map[string]string{"PUBLISH_KEY": lockedKey, "PUBLISH_KEY_PASSPHRASE": "wrong"}),
			"OPENPSIRT_PUBLISH_KEY",
		},
		"a passphrase for a key that is not locked": {
			publishingWith(map[string]string{"PUBLISH_KEY": plainKey, "PUBLISH_KEY_PASSPHRASE": keyPassphrase}),
			"OPENPSIRT_PUBLISH_KEY",
		},
		"a passphrase with no key": {
			publishingWith(map[string]string{"PUBLISH_KEY_PASSPHRASE": keyPassphrase}),
			"OPENPSIRT_PUBLISH_KEY_PASSPHRASE",
		},
		"a zero rate": {
			publishingWith(map[string]string{"PUBLISH_RATE": "0"}),
			"OPENPSIRT_PUBLISH_RATE",
		},
		"a negative rate": {
			publishingWith(map[string]string{"PUBLISH_RATE": "-5"}),
			"OPENPSIRT_PUBLISH_RATE",
		},
		"a rate with publishing off": {
			map[string]string{"PUBLISH_RATE": "30"},
			"OPENPSIRT_PUBLISH_RATE",
		},
		"every address a trusted proxy": {
			publishingWith(map[string]string{"TRUSTED_SOURCES": "0.0.0.0/0"}),
			"OPENPSIRT_TRUSTED_SOURCES",
		},
		"trusted proxies and no header with publishing off": {
			map[string]string{"TRUSTED_SOURCES": "10.0.0.0/8"},
			"OPENPSIRT_TRUSTED_HEADER",
		},
		"a key with publishing off": {
			map[string]string{"PUBLISH_KEY": plainKey},
			"OPENPSIRT_PUBLISH_KEY",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(tc.given)
			if err == nil {
				t.Fatal("started")
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("refused as %q, which does not name %s", err, tc.names)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Errorf("the refusal repeats the key: %q", err)
			}
		})
	}
}
