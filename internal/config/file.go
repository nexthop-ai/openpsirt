// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// LoadFile reads configuration from a TOML file, refusing where the
// environment holds any variable of this deployment's own.
//
// environ is the process environment in the form os.Environ gives it. One
// source per deployment: a value set in both would leave a setting's value a
// question of which source won, so a variable beside a file is refused rather
// than ignored or preferred.
//
// The file holds secrets, so one that anybody but its owner may read or
// write is refused. A key the table does not know, and a value of the wrong
// type, are refused naming the key; a malformed file is refused naming the
// line. What the file holds is then read by the same loader the environment's
// values are, so every default and every refusal is the environment's, and
// the refusal names the key rather than the variable.
func LoadFile(path string, environ []string) (Config, error) {
	var ours []string
	for _, kv := range environ {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, envPrefix) {
			ours = append(ours, name)
		}
	}
	if len(ours) > 0 {
		sort.Strings(ours)
		return Config{}, fmt.Errorf("%s is set beside the configuration file %s: a deployment is "+
			"configured by one or the other, so move each into the file and unset it",
			strings.Join(ours, ", "), path)
	}

	info, err := os.Stat(path)
	if err != nil {
		return Config{}, fmt.Errorf("configuration file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("configuration file %s: not a regular file", path)
	}
	if open := info.Mode().Perm() & 0o077; open != 0 {
		return Config{}, fmt.Errorf("configuration file %s: mode %04o lets somebody other than its "+
			"owner read or change it, and it holds secrets: set it to 0600 (chmod 600 %s)",
			path, info.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the path an operator named on the command line
	if err != nil {
		return Config{}, fmt.Errorf("configuration file: %w", err)
	}
	given, err := parseFile(string(raw))
	if err != nil {
		return Config{}, fmt.Errorf("configuration file %s: %w", path, err)
	}
	c, err := load(given)
	return c, InFile(err)
}

// parseFile reads a configuration file into the values the loader reads,
// keyed by environment name and spelled as the environment spells them.
func parseFile(raw string) (map[string]string, error) {
	var tree map[string]any
	if _, err := toml.Decode(raw, &tree); err != nil {
		var parse toml.ParseError
		if errors.As(err, &parse) {
			return nil, fmt.Errorf("line %d: %s", parse.Position.Line, parse.Message)
		}
		return nil, err
	}
	byKey := map[string]setting{}
	for _, one := range settings {
		byKey[one.file] = one
	}
	given := map[string]string{}
	if err := walk(tree, "", byKey, given); err != nil {
		return nil, err
	}
	return given, nil
}

// walk reads every key under one table, refusing one the table of settings
// does not know. Keys are visited in order so that a file with several
// mistakes is refused for the same one every time.
func walk(tree map[string]any, under string, byKey map[string]setting, given map[string]string) error {
	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := name
		if under != "" {
			key = under + "." + name
		}
		value := tree[name]
		if one, ok := byKey[key]; ok {
			spelled, err := spell(one, value)
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			given[one.env] = spelled
			continue
		}
		table, isTable := value.(map[string]any)
		if !isTable || !section(key) {
			return fmt.Errorf("%s is not a setting: check its spelling and the table it is under", key)
		}
		if err := walk(table, key, byKey, given); err != nil {
			return err
		}
	}
	return nil
}

// section reports whether a key is a table that holds settings.
func section(key string) bool {
	for _, one := range settings {
		if strings.HasPrefix(one.file, key+".") {
			return true
		}
	}
	return false
}

// spell writes a value from a file the way the environment would carry it,
// refusing one of the wrong type rather than converting it: a quoted number or
// a switch written as a word is a mistake a file makes visible.
func spell(one setting, value any) (string, error) {
	switch one.kind {
	case text, duration:
		if s, ok := value.(string); ok {
			return s, nil
		}
		if one.kind == duration {
			return "", fmt.Errorf("want a duration written as a string, such as \"30s\", got %s", typeOf(value))
		}
		return "", fmt.Errorf("want a string, got %s", typeOf(value))
	case number:
		if n, ok := value.(int64); ok {
			return strconv.FormatInt(n, 10), nil
		}
		return "", fmt.Errorf("want a whole number, got %s", typeOf(value))
	case boolean:
		if b, ok := value.(bool); ok {
			return strconv.FormatBool(b), nil
		}
		return "", fmt.Errorf("want true or false, got %s", typeOf(value))
	case list:
		items, ok := value.([]any)
		if !ok {
			return "", fmt.Errorf("want a list of strings, such as [\"a\", \"b\"], got %s", typeOf(value))
		}
		names := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("want a list of strings, and one entry is %s", typeOf(item))
			}
			// The loader reads a list as the environment carries it, joined
			// with commas, so an entry holding one would be read as two.
			if strings.Contains(s, ",") {
				return "", fmt.Errorf("an entry holds a comma, which would be read as two: %q", s)
			}
			names = append(names, s)
		}
		return strings.Join(names, ","), nil
	}
	return "", fmt.Errorf("no reading for this setting's type")
}

// typeOf names a decoded value's type the way the file format does.
func typeOf(value any) string {
	switch value.(type) {
	case string:
		return "a string"
	case int64:
		return "a whole number"
	case float64:
		return "a fractional number"
	case bool:
		return "true or false"
	case []any, []map[string]any:
		return "a list"
	case map[string]any:
		return "a table"
	}
	return "a date or time"
}

// InFile rewrites a refusal to name each setting by its key in a
// configuration file rather than by its environment variable, so that
// somebody configuring a deployment by file is told what to change in the
// file. It keeps what it wraps, for errors.Is and errors.As.
//
// Longer names are replaced first, so a name that begins another is never
// replaced inside it.
func InFile(err error) error {
	if err == nil {
		return nil
	}
	ordered := slices.Clone(settings)
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i].env) > len(ordered[j].env) })
	pairs := make([]string, 0, 2*len(ordered))
	for _, one := range ordered {
		pairs = append(pairs, envPrefix+one.env, one.file)
	}
	said := strings.NewReplacer(pairs...).Replace(err.Error())
	if said == err.Error() {
		return err
	}
	return renamed{said: said, err: err}
}

// renamed is a refusal whose words were rewritten.
type renamed struct {
	said string
	err  error
}

func (r renamed) Error() string { return r.said }
func (r renamed) Unwrap() error { return r.err }
