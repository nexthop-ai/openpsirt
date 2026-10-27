// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"errors"
	"io"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/docread"
	md "github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Limits bounds one upload's documents. A count past its bound refuses the
// document; a text past its bound is cut.
type Limits struct {
	// MaxBytes is the upload's documents' size once decompressed, together
	// with the text their results are worded with from their rules' message
	// strings, and MaxPart one document's size once decompressed.
	MaxBytes int64
	MaxPart  int64
	// MaxCompressed is the upload's size as it is sent, and
	// MaxPartCompressed one document's: compressed where it was compressed.
	MaxCompressed     int64
	MaxPartCompressed int64
	// MaxSnippet is the longest source text kept for one location, in bytes.
	MaxSnippet int
	MaxDepth   int
	MaxRuns    int
	// MaxResults is per run, and MaxRules per run across every component.
	MaxResults int
	MaxRules   int
	// MaxLocations is per result, its own and related locations together.
	MaxLocations int
	// MaxSteps is per result, across every flow it states.
	MaxSteps int
	// MaxModules and MaxBases are per run.
	MaxModules int
	MaxBases   int
	// MaxChain is how many named starting points one address may pass
	// through.
	MaxChain int
	// MaxProperties is per property bag.
	MaxProperties int
	// MaxText is the longest message or description kept, in bytes.
	MaxText int
	// MaxHeld is how many things the upload's documents hold together:
	// results, rules, locations, steps, invocations and the members of
	// every list and map they carry. Each costs memory however little of the
	// document it took, so this is the bound on what reading holds beyond
	// the text.
	MaxHeld int
}

// DefaultLimits are the bounds a reader uses where it is given none.
//
// A thing held costs about 200 bytes of memory however few bytes of the
// document it took, so MaxHeld at its default bounds that to about 200 MB on
// top of MaxBytes.
//
// Left unset, one document's bound is the upload's, and each bound as sent is
// its decompressed counterpart, so a document sent without compression is
// bounded as it is held. Analyzer output measured here compresses 7 to 17
// times over, so a compressed upload meets the decompressed bound first. One
// document may take the whole upload's bounds, which is what a tool's
// per-unit documents merged into one take.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:          256 << 20,
		MaxPart:           256 << 20,
		MaxCompressed:     256 << 20,
		MaxPartCompressed: 256 << 20,
		MaxSnippet:        4 << 10,
		MaxDepth:          64,
		MaxRuns:           16,
		MaxResults:        100_000,
		MaxRules:          10_000,
		MaxLocations:      1_000,
		MaxSteps:          10_000,
		MaxModules:        1_000,
		MaxBases:          1_000,
		MaxChain:          16,
		MaxProperties:     256,
		MaxText:           16 << 10,
		MaxHeld:           1_000_000,
	}
}

// DefaultDocuments is how many documents one upload may carry where nobody
// has said. A tool writing a document per unit has them merged into one
// before they are sent.
const DefaultDocuments = 16

// OrDefault fills in anything left unset, so a caller that wants one bound
// changed does not have to restate the rest.
func (l Limits) OrDefault() Limits {
	d := DefaultLimits()
	for _, f := range []struct{ v, d *int }{
		{&l.MaxDepth, &d.MaxDepth}, {&l.MaxRuns, &d.MaxRuns}, {&l.MaxResults, &d.MaxResults},
		{&l.MaxRules, &d.MaxRules}, {&l.MaxLocations, &d.MaxLocations}, {&l.MaxSteps, &d.MaxSteps},
		{&l.MaxModules, &d.MaxModules}, {&l.MaxBases, &d.MaxBases}, {&l.MaxChain, &d.MaxChain},
		{&l.MaxProperties, &d.MaxProperties}, {&l.MaxText, &d.MaxText}, {&l.MaxHeld, &d.MaxHeld},
		{&l.MaxSnippet, &d.MaxSnippet},
	} {
		if *f.v <= 0 {
			*f.v = *f.d
		}
	}
	// One document takes the whole upload's bound, and the sizes as sent take
	// the decompressed ones, so raising the upload's bound raises the rest.
	for _, f := range []struct{ v, d *int64 }{
		{&l.MaxBytes, &d.MaxBytes}, {&l.MaxPart, &l.MaxBytes},
		{&l.MaxCompressed, &l.MaxBytes}, {&l.MaxPartCompressed, &l.MaxPart},
	} {
		if *f.v <= 0 {
			*f.v = *f.d
		}
	}
	return l
}

// Upload reads the documents of one upload within one budget. What they
// hold is in memory at once, so their size, the text worded for their
// results and what they hold are bounded across the upload together.
type Upload struct {
	lim Limits
	// bytes is what the documents read so far took once decompressed, and
	// the text worded for their results.
	bytes int64
	held  int
}

// NewUpload is an upload that has read nothing, within lim, with any bound
// it leaves unset at its default.
func NewUpload(lim Limits) *Upload { return &Upload{lim: lim.OrDefault()} }

// Read reads the upload's next document, compressed with gzip or not. A
// document is read within what is left of the upload's decompressed bound and
// within its own, whichever is less.
func (u *Upload) Read(r io.Reader) (Log, error) {
	left := u.lim.MaxBytes - u.bytes
	part := left > u.lim.MaxPart
	if part {
		left = u.lim.MaxPart
	}
	plain, err := gunzipped(r, left)
	if err != nil {
		return Log{}, err
	}
	counted := &counting{r: plain}
	b := docread.NewJSON(counted, left, u.lim.MaxDepth)
	b.BoundMembers("properties", u.lim.MaxProperties, func() error {
		return over("members in a property bag", u.lim.MaxProperties)
	})
	rd := reader{b: b, lim: u.lim, up: u, read: counted}
	log, err := rd.log()
	if err == nil {
		err = b.End()
	}
	u.bytes += counted.n
	switch {
	case errors.Is(err, docread.ErrTooLarge) && part:
		return Log{}, over(partBytes, int(u.lim.MaxPart))
	case errors.Is(err, docread.ErrTooLarge) && left < u.lim.MaxBytes, err == nil && u.bytes > u.lim.MaxBytes:
		return Log{}, over(uploadBytes, int(u.lim.MaxBytes))
	case err != nil:
		return Log{}, b.Refused("reading SARIF", err)
	}
	return log, nil
}

// Sent refuses a document past its bound as it was sent, compressed or not.
func (l Limits) Sent(size int64) error {
	if size > l.MaxPartCompressed {
		return over("bytes in one document as it was sent", int(l.MaxPartCompressed))
	}
	return nil
}

// What the bounds on an upload's size and one document's size count.
const (
	uploadBytes = "bytes across the upload's documents and the text worded for their results"
	partBytes   = "bytes in one document once decompressed"
)

// counting counts what passes through it.
type counting struct {
	r io.Reader
	n int64
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type reader struct {
	b    *docread.JSON
	lim  Limits
	up   *Upload
	read *counting
}

// hold counts one more thing held, refusing the upload past the bound.
func (rd *reader) hold() error {
	rd.up.held++
	if rd.up.held > rd.lim.MaxHeld {
		return over("results, locations and other entries across the upload's documents", rd.lim.MaxHeld)
	}
	return nil
}

// spend counts text worded for a result against the upload's size, which it
// costs as much as text the document carried.
func (rd *reader) spend(n int) error {
	rd.up.bytes += int64(n)
	if rd.up.bytes+rd.read.n > rd.lim.MaxBytes {
		return over(uploadBytes, int(rd.lim.MaxBytes))
	}
	return nil
}

// over refuses a count past its bound, naming the bound.
func over(what string, most int) error {
	return refusal.Errorf("more %s than the configured limit of %d", what, most)
}

func (rd *reader) text(s string) string { return bound.Head(s, rd.lim.MaxText) }

func (rd *reader) log() (Log, error) {
	var log Log
	version := ""
	err := rd.b.Object(func(key string) error {
		switch key {
		case "version":
			v, err := rd.b.Str()
			version = v
			return err
		case "runs":
			return rd.b.Array(func() error {
				if len(log.Runs) == rd.lim.MaxRuns {
					return over("runs", rd.lim.MaxRuns)
				}
				if err := rd.hold(); err != nil {
					return err
				}
				run, err := rd.run()
				if err != nil {
					return err
				}
				log.Runs = append(log.Runs, run)
				return nil
			})
		default:
			return rd.b.Skip()
		}
	})
	if err != nil {
		return Log{}, err
	}
	if version != Version {
		return Log{}, refusal.Errorf("SARIF version %q is not %s", bound.Head(version, docread.MostQuoted), Version)
	}
	return log, nil
}

// pending is what a result names by reference, settled once the whole run is
// read: a run's members may arrive in any order, and a result citing a rule by
// position or a message by identifier may precede the rules it cites.
type pending struct {
	ruleIndex *int
	// ruleComponent is the position among the tool's extensions of the one
	// the result's rule belongs to, where the result names one.
	ruleComponent *int
	messageID     string
	arguments     []string
	hasOwnText    bool
}

func (rd *reader) run() (Run, error) {
	var run Run
	var waiting []pending
	err := rd.b.Object(func(key string) error {
		switch key {
		case "tool":
			return rd.tool(&run)
		case "results":
			results := []Result{}
			ran, err := rd.b.ArrayOrNull(func() error {
				if len(results) == rd.lim.MaxResults {
					return over("results in a run", rd.lim.MaxResults)
				}
				if err := rd.hold(); err != nil {
					return err
				}
				res, p, err := rd.result(&run.Discarded)
				if err != nil {
					return err
				}
				results = append(results, res)
				waiting = append(waiting, p)
				return nil
			})
			if ran {
				run.Ran, run.Results = true, results
			}
			return err
		case "invocations":
			return rd.b.Array(func() error {
				if err := rd.hold(); err != nil {
					return err
				}
				inv, err := rd.invocation()
				run.Invocations = append(run.Invocations, inv)
				return err
			})
		case "automationDetails":
			return rd.b.Object(func(key string) error {
				if key == "id" {
					id, err := rd.b.Str()
					run.AutomationID = rd.text(id)
					return err
				}
				return rd.b.Skip()
			})
		case "versionControlProvenance":
			return rd.b.Array(func() error {
				if len(run.Modules) == rd.lim.MaxModules {
					return over("repositories in a run", rd.lim.MaxModules)
				}
				if err := rd.hold(); err != nil {
					return err
				}
				m, err := rd.module()
				run.Modules = append(run.Modules, m)
				return err
			})
		case "originalUriBaseIds":
			run.Bases = map[string]ArtifactLocation{}
			return rd.b.Object(func(name string) error {
				if len(run.Bases) == rd.lim.MaxBases {
					return over("named starting points in a run", rd.lim.MaxBases)
				}
				if err := rd.hold(); err != nil {
					return err
				}
				loc, err := rd.artifactLocation()
				run.Bases[name] = loc
				return err
			})
		case "artifacts":
			return rd.b.Array(func() error {
				return rd.b.Object(func(key string) error {
					if key == "contents" {
						run.Discarded.Contents++
					}
					return rd.b.Skip()
				})
			})
		case "properties":
			return rd.runProperties(&run.Properties)
		default:
			return rd.b.Skip()
		}
	})
	if err != nil {
		return Run{}, err
	}
	if err := chained(run.Bases, rd.lim.MaxChain); err != nil {
		return Run{}, err
	}
	if err := rd.settle(&run, waiting); err != nil {
		return Run{}, err
	}
	return run, nil
}

// chained refuses a run whose named starting points loop, or chain further
// than most.
func chained(bases map[string]ArtifactLocation, most int) error {
	for name := range bases {
		seen := map[string]bool{}
		for at := name; at != ""; at = bases[at].Base {
			if seen[at] {
				return refusal.Errorf("the starting point %q is defined in terms of itself", bound.Head(name, docread.MostQuoted))
			}
			seen[at] = true
			if len(seen) > most {
				return over("starting points in one chain", most)
			}
			if _, ok := bases[at]; !ok {
				break
			}
		}
	}
	return nil
}

// settle fills in what each result named by reference.
func (rd *reader) settle(run *Run, waiting []pending) error {
	byID := map[string][]int{}
	byComponent := map[int][]int{}
	for j, rule := range run.Tool.Rules {
		byID[rule.ID] = append(byID[rule.ID], j)
		byComponent[rule.component] = append(byComponent[rule.component], j)
	}
	for i := range run.Results {
		res, p := &run.Results[i], waiting[i]
		rule := ruleOf(run.Tool.Rules, byID, byComponent, res.RuleID, p)
		if rule != nil && res.RuleID == "" {
			res.RuleID = rule.ID
		}
		if res.Level == "" && rule != nil {
			res.Level = rule.DefaultLevel
		}
		if res.Level == "" {
			res.Level = "warning"
		}
		var stringsOf map[string]string
		if rule != nil {
			stringsOf = rule.messages
		}
		if !p.hasOwnText || len(p.arguments) > 0 {
			res.Message = rd.text(worded(res.Message, p.messageID, p.arguments, stringsOf, rd.lim.MaxText))
			if err := rd.spend(len(res.Message)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ruleOf is the rule a result cites. Its identifier is looked for first,
// whole and then by its leading components, within the component the result
// names where it names one. A position is
// read only where the result states no identifier, and only within the
// component it names: the driver, where it names none.
func ruleOf(rules []Rule, byID map[string][]int, byComponent map[int][]int, id string, p pending) *Rule {
	component := 0
	if p.ruleComponent != nil {
		component = *p.ruleComponent + 1
	}
	// A hierarchical identifier names a rule by its leading components:
	// "CA5350/md5" is reported under the rule "CA5350".
	for cut := id; cut != ""; {
		for _, j := range byID[cut] {
			if p.ruleComponent == nil || rules[j].component == component {
				return &rules[j]
			}
		}
		i := strings.LastIndexByte(cut, '/')
		if i <= 0 {
			return nil
		}
		cut = cut[:i]
	}
	if p.ruleIndex == nil {
		return nil
	}
	at := byComponent[component]
	if n := *p.ruleIndex; n >= 0 && n < len(at) {
		return &rules[at[n]]
	}
	return nil
}

func (rd *reader) tool(run *Run) error {
	extensions := 0
	// component reads the driver, at 0, or an extension, from 1 on.
	component := func(at int) error {
		driver := at == 0
		return rd.b.Object(func(key string) error {
			switch key {
			case "name":
				if !driver {
					return rd.b.Skip()
				}
				s, err := rd.b.Str()
				run.Tool.Name = rd.text(s)
				return err
			case "version", "semanticVersion":
				if !driver {
					return rd.b.Skip()
				}
				s, err := rd.b.Str()
				if run.Tool.Version == "" || key == "version" {
					run.Tool.Version = rd.text(s)
				}
				return err
			case "rules":
				return rd.b.Array(func() error {
					if len(run.Tool.Rules) == rd.lim.MaxRules {
						return over("rules in a run", rd.lim.MaxRules)
					}
					if err := rd.hold(); err != nil {
						return err
					}
					rule, err := rd.rule(&run.Discarded)
					rule.component = at
					run.Tool.Rules = append(run.Tool.Rules, rule)
					return err
				})
			default:
				return rd.b.Skip()
			}
		})
	}
	return rd.b.Object(func(key string) error {
		switch key {
		case "driver":
			return component(0)
		case "extensions":
			return rd.b.Array(func() error {
				extensions++
				return component(extensions)
			})
		default:
			return rd.b.Skip()
		}
	})
}

func (rd *reader) rule(discarded *Discarded) (Rule, error) {
	var rule Rule
	err := rd.b.Object(func(key string) error {
		switch key {
		case "id":
			s, err := rd.b.Str()
			rule.ID = rd.text(s)
			return err
		case "name":
			s, err := rd.b.Str()
			rule.Name = rd.text(s)
			return err
		case "shortDescription":
			s, err := rd.message(discarded, nil)
			if rule.Description == "" {
				rule.Description = s
			}
			return err
		case "fullDescription":
			s, err := rd.message(discarded, nil)
			if s != "" {
				rule.Description = s
			}
			return err
		case "helpUri":
			s, err := rd.b.Str()
			rule.HelpURI = rd.text(s)
			return err
		case "messageStrings":
			rule.messages = map[string]string{}
			return rd.b.Object(func(id string) error {
				s, err := rd.message(discarded, nil)
				if err != nil || len(rule.messages) == rd.lim.MaxRules {
					return err
				}
				rule.messages[id] = s
				return rd.hold()
			})
		case "defaultConfiguration":
			return rd.b.Object(func(key string) error {
				if key == "level" {
					s, err := rd.b.Str()
					rule.DefaultLevel = level(s)
					return err
				}
				return rd.b.Skip()
			})
		case "properties":
			return rd.properties(func(key string) error {
				switch key {
				case "tags":
					return rd.b.Array(func() error {
						s, err := rd.b.Str()
						if err != nil || len(rule.Tags) == rd.lim.MaxRules {
							return err
						}
						rule.Tags = append(rule.Tags, rd.text(s))
						return rd.hold()
					})
				case "security-severity":
					s, err := rd.b.Str()
					rule.SecuritySeverity = bound.Head(s, docread.MostQuoted)
					return err
				case "precision":
					s, err := rd.b.Str()
					rule.Precision = bound.Head(s, docread.MostQuoted)
					return err
				default:
					return rd.b.Skip()
				}
			})
		default:
			return rd.b.Skip()
		}
	})
	return rule, err
}

// level is a result level the format defines, and empty for anything else.
func level(s string) string {
	switch s {
	case "none", "note", "warning", "error":
		return s
	}
	return ""
}

// message reads a message object's text. A message with only markdown is
// reduced to the words it shows, which are shown encoded and never rendered.
// Where p is given, it records what the message cites by identifier.
func (rd *reader) message(discarded *Discarded, p *pending) (string, error) {
	var text, markdown string
	hasText := false
	err := rd.b.Object(func(key string) error {
		switch key {
		case "text":
			s, err := rd.b.Str()
			text, hasText = s, true
			return err
		case "markdown":
			s, err := rd.b.Str()
			markdown = s
			return err
		case "id":
			s, err := rd.b.Str()
			if p != nil {
				p.messageID = bound.Head(s, docread.MostQuoted)
			}
			return err
		case "arguments":
			return rd.b.Array(func() error {
				s, err := rd.b.Str()
				if err != nil || p == nil || len(p.arguments) == rd.lim.MaxLocations {
					return err
				}
				p.arguments = append(p.arguments, rd.text(s))
				return rd.hold()
			})
		default:
			return rd.b.Skip()
		}
	})
	if markdown != "" {
		discarded.Markdown++
		if !hasText {
			text, hasText = md.Text(bound.Head(markdown, rd.lim.MaxText)), true
		}
	}
	if p != nil {
		p.hasOwnText = hasText
	}
	return rd.text(text), err
}

func (rd *reader) result(discarded *Discarded) (Result, pending, error) {
	var res Result
	var p pending
	steps := 0
	err := rd.b.Object(func(key string) error {
		switch key {
		case "ruleId":
			s, err := rd.b.Str()
			res.RuleID = rd.text(s)
			return err
		case "rule":
			return rd.b.Object(func(key string) error {
				switch key {
				case "id":
					s, err := rd.b.Str()
					if res.RuleID == "" {
						res.RuleID = rd.text(s)
					}
					return err
				case "index":
					n, err := rd.b.Int()
					p.ruleIndex = n
					return err
				case "toolComponent":
					return rd.b.Object(func(key string) error {
						if key != "index" {
							return rd.b.Skip()
						}
						n, err := rd.b.Int()
						p.ruleComponent = n
						return err
					})
				default:
					return rd.b.Skip()
				}
			})
		case "ruleIndex":
			n, err := rd.b.Int()
			if p.ruleIndex == nil {
				p.ruleIndex = n
			}
			return err
		case "level":
			s, err := rd.b.Str()
			res.Level = level(s)
			return err
		case "kind":
			s, err := rd.b.Str()
			res.Kind = resultKind(s)
			return err
		case "suppressions":
			return rd.b.Array(func() error {
				status := ""
				err := rd.b.Object(func(key string) error {
					if key != "status" {
						return rd.b.Skip()
					}
					s, err := rd.b.Str()
					status = s
					return err
				})
				// A suppression stating no status is in force.
				if status == "" || status == "accepted" {
					res.Suppressed = true
				}
				return err
			})
		case "baselineState":
			s, err := rd.b.Str()
			res.Absent = s == "absent"
			return err
		case "message":
			s, err := rd.message(discarded, &p)
			res.Message = s
			return err
		case "locations", "relatedLocations":
			return rd.b.Array(func() error {
				if len(res.Locations)+len(res.Related) == rd.lim.MaxLocations {
					return over("locations in a result", rd.lim.MaxLocations)
				}
				if err := rd.hold(); err != nil {
					return err
				}
				loc, err := rd.location(discarded)
				if key == "locations" {
					res.Locations = append(res.Locations, loc)
				} else {
					res.Related = append(res.Related, loc)
				}
				return err
			})
		case "codeFlows":
			first := true
			return rd.b.Array(func() error {
				keep := first
				first = false
				return rd.codeFlow(discarded, &res, keep, &steps)
			})
		case "partialFingerprints", "fingerprints":
			if res.Fingerprints == nil {
				res.Fingerprints = map[string]string{}
			}
			return rd.b.Object(func(scheme string) error {
				s, err := rd.b.Str()
				if err != nil || len(res.Fingerprints) == rd.lim.MaxLocations {
					return err
				}
				res.Fingerprints[bound.Head(scheme, docread.MostQuoted)] = rd.text(s)
				return rd.hold()
			})
		case "fixes":
			return rd.b.Array(func() error {
				discarded.Fixes++
				return rd.b.Skip()
			})
		case "properties":
			return rd.properties(func(string) error { return rd.b.Skip() })
		default:
			return rd.b.Skip()
		}
	})
	if res.Kind == "" {
		res.Kind = "fail"
	}
	return res, p, err
}

// resultKind is a result kind the format defines, and empty for anything
// else.
func resultKind(s string) string {
	switch s {
	case "pass", "open", "informational", "notApplicable", "review", "fail":
		return s
	}
	return ""
}

// codeFlow reads one flow. The steps of the first thread of the first flow
// are kept; every step of every flow counts toward the bound.
func (rd *reader) codeFlow(discarded *Discarded, res *Result, keep bool, steps *int) error {
	return rd.b.Object(func(key string) error {
		if key != "threadFlows" {
			return rd.b.Skip()
		}
		first := true
		return rd.b.Array(func() error {
			keepThread := keep && first
			first = false
			return rd.b.Object(func(key string) error {
				if key != "locations" {
					return rd.b.Skip()
				}
				return rd.b.Array(func() error {
					*steps++
					if *steps > rd.lim.MaxSteps {
						return over("flow steps in a result", rd.lim.MaxSteps)
					}
					step, err := rd.step(discarded)
					if err != nil || !keepThread {
						return err
					}
					res.Steps = append(res.Steps, step)
					return rd.hold()
				})
			})
		})
	})
}

func (rd *reader) step(discarded *Discarded) (Step, error) {
	var step Step
	err := rd.b.Object(func(key string) error {
		switch key {
		case "location":
			loc, err := rd.location(discarded)
			step.Location = loc
			return err
		case "nestingLevel":
			n, err := rd.b.Int()
			step.Depth = n
			return err
		default:
			return rd.b.Skip()
		}
	})
	return step, err
}

func (rd *reader) location(discarded *Discarded) (Location, error) {
	var loc Location
	err := rd.b.Object(func(key string) error {
		switch key {
		case "physicalLocation":
			return rd.b.Object(func(key string) error {
				switch key {
				case "artifactLocation":
					a, err := rd.artifactLocation()
					loc.URI, loc.Base = a.URI, a.Base
					return err
				case "region":
					return rd.region(&loc, false)
				case "contextRegion":
					return rd.region(&loc, true)
				default:
					return rd.b.Skip()
				}
			})
		case "logicalLocations":
			return rd.b.Array(func() error {
				return rd.b.Object(func(key string) error {
					switch key {
					case "fullyQualifiedName", "name":
						s, err := rd.b.Str()
						if loc.Function == "" || key == "fullyQualifiedName" {
							loc.Function = rd.text(s)
						}
						return err
					default:
						return rd.b.Skip()
					}
				})
			})
		case "message":
			s, err := rd.message(discarded, nil)
			loc.Message = s
			return err
		default:
			return rd.b.Skip()
		}
	})
	return loc, err
}

// region reads a region's lines and columns into loc, and its source text
// with the line it starts at. A context region's lines are not the
// location's, so only its text is taken, and it is preferred to the region's
// own, which is the narrower of the two.
func (rd *reader) region(loc *Location, context bool) error {
	var r Location
	var snippet string
	err := rd.b.Object(func(key string) error {
		var into *int
		switch key {
		case "startLine":
			into = &r.StartLine
		case "startColumn":
			into = &r.StartColumn
		case "endLine":
			into = &r.EndLine
		case "endColumn":
			into = &r.EndColumn
		case "snippet":
			return rd.b.Object(func(key string) error {
				if key != "text" {
					return rd.b.Skip()
				}
				s, err := rd.b.Str()
				snippet = bound.Head(s, rd.lim.MaxSnippet)
				return err
			})
		default:
			return rd.b.Skip()
		}
		n, err := rd.b.Int()
		if n != nil && *n > 0 {
			*into = *n
		}
		return err
	})
	switch {
	case context:
		if snippet != "" {
			loc.Snippet, loc.SnippetLine, loc.widest = snippet, r.StartLine, true
		}
	default:
		loc.StartLine, loc.StartColumn, loc.EndLine, loc.EndColumn = r.StartLine, r.StartColumn, r.EndLine, r.EndColumn
		if snippet != "" && !loc.widest {
			loc.Snippet, loc.SnippetLine = snippet, r.StartLine
		}
	}
	return err
}

func (rd *reader) artifactLocation() (ArtifactLocation, error) {
	var a ArtifactLocation
	err := rd.b.Object(func(key string) error {
		switch key {
		case "uri":
			s, err := rd.b.Str()
			a.URI = rd.text(s)
			return err
		case "uriBaseId":
			s, err := rd.b.Str()
			a.Base = bound.Head(s, docread.MostQuoted)
			return err
		default:
			return rd.b.Skip()
		}
	})
	return a, err
}

func (rd *reader) module() (Module, error) {
	var m Module
	err := rd.b.Object(func(key string) error {
		switch key {
		case "repositoryUri":
			s, err := rd.b.Str()
			m.Repository = rd.text(s)
			return err
		case "revisionId":
			s, err := rd.b.Str()
			m.Revision = bound.Head(s, docread.MostQuoted)
			return err
		case "mappedTo":
			a, err := rd.artifactLocation()
			m.URI, m.Base = a.URI, a.Base
			return err
		default:
			return rd.b.Skip()
		}
	})
	return m, err
}

func (rd *reader) invocation() (Invocation, error) {
	var inv Invocation
	err := rd.b.Object(func(key string) error {
		switch key {
		case "exitCode":
			n, err := rd.b.Int()
			inv.ExitCode = n
			return err
		case "executionSuccessful":
			v, err := rd.b.Bool()
			inv.Successful = v
			return err
		case "workingDirectory":
			a, err := rd.artifactLocation()
			inv.WorkingDirectory = a
			return err
		case "toolExecutionNotifications", "toolConfigurationNotifications":
			return rd.b.Array(func() error {
				lvl, id := "", ""
				err := rd.b.Object(func(key string) error {
					switch key {
					case "level":
						s, err := rd.b.Str()
						lvl = s
						return err
					case "descriptor":
						return rd.b.Object(func(key string) error {
							if key == "id" {
								s, err := rd.b.Str()
								id = bound.Head(s, docread.MostQuoted)
								return err
							}
							return rd.b.Skip()
						})
					default:
						return rd.b.Skip()
					}
				})
				if err != nil {
					return err
				}
				switch {
				case strings.HasSuffix(id, expectedFiles):
					inv.Expected++
				case strings.HasSuffix(id, extractedFiles):
					inv.Extracted++
				}
				if lvl == "error" {
					inv.Errors++
				}
				return nil
			})
		default:
			return rd.b.Skip()
		}
	})
	return inv, err
}

// Property names under this deployment's prefix, which the upload client
// writes into each run.
const (
	propUnitsExpected = "openpsirt/unitsExpected"
	propUnitsAnalyzed = "openpsirt/unitsAnalyzed"
	propClient        = "openpsirt/client"
	propChanged       = "openpsirt/changed"
	propSeries        = "openpsirt/series"
	propBuilt         = "openpsirt/built"
	propCommit        = "openpsirt/commit"
	propSalt          = "openpsirt/salt"
)

// properties reads one property bag. Every bag the document holds, read or
// walked past, is refused with more members than the bound, as the reader's
// branch or tag counts them.
func (rd *reader) properties(fn func(key string) error) error {
	return rd.b.Object(fn)
}

func (rd *reader) runProperties(p *RunProperties) error {
	str := func(into *string) error {
		s, err := rd.b.Str()
		*into = bound.Head(s, docread.MostQuoted*4)
		return err
	}
	return rd.properties(func(key string) error {
		switch key {
		case propUnitsExpected:
			n, err := rd.b.Int()
			p.UnitsExpected = n
			return err
		case propUnitsAnalyzed:
			n, err := rd.b.Int()
			p.UnitsAnalyzed = n
			return err
		case propClient:
			return str(&p.Client)
		case propSeries:
			return str(&p.Series)
		case propBuilt:
			return str(&p.Built)
		case propCommit:
			return str(&p.Commit)
		case propSalt:
			return str(&p.Salt)
		case propChanged:
			return rd.b.Array(func() error {
				s, err := rd.b.Str()
				if len(p.Changed) == rd.lim.MaxModules {
					return over("changed repositories in a run", rd.lim.MaxModules)
				}
				if err != nil {
					return err
				}
				p.Changed = append(p.Changed, rd.text(s))
				return rd.hold()
			})
		default:
			if strings.HasPrefix(key, "openpsirt/") {
				return refusal.Errorf("run property %q is not one this deployment reads", bound.Head(key, docread.MostQuoted))
			}
			return rd.b.Skip()
		}
	})
}
