// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"io"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/docread"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Limits bounds one document. A count past its bound refuses the document;
// a text past its bound is cut.
type Limits struct {
	// MaxBytes is the document's size once decompressed.
	MaxBytes int64
	MaxDepth int
	MaxRuns  int
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
}

// DefaultLimits are the bounds a reader uses where it is given none.
//
// The heap a result costs is its locations and steps, so results and steps
// are bounded together: a run at every ceiling at once is the largest thing
// read, and none is close to it.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:      256 << 20,
		MaxDepth:      64,
		MaxRuns:       16,
		MaxResults:    100_000,
		MaxRules:      10_000,
		MaxLocations:  1_000,
		MaxSteps:      10_000,
		MaxModules:    1_000,
		MaxBases:      1_000,
		MaxChain:      16,
		MaxProperties: 256,
		MaxText:       16 << 10,
	}
}

// DefaultDocuments is how many documents one upload may carry where nobody
// has said. The upload client merges a tool's per-unit documents into one
// run, so a plain upload of one document per unit meets this.
const DefaultDocuments = 16

// OrDefault fills in anything left unset, so a caller that wants one bound
// changed does not have to restate the rest.
func (l Limits) OrDefault() Limits {
	d := DefaultLimits()
	for _, f := range []struct{ v, d *int }{
		{&l.MaxDepth, &d.MaxDepth}, {&l.MaxRuns, &d.MaxRuns}, {&l.MaxResults, &d.MaxResults},
		{&l.MaxRules, &d.MaxRules}, {&l.MaxLocations, &d.MaxLocations}, {&l.MaxSteps, &d.MaxSteps},
		{&l.MaxModules, &d.MaxModules}, {&l.MaxBases, &d.MaxBases}, {&l.MaxChain, &d.MaxChain},
		{&l.MaxProperties, &d.MaxProperties}, {&l.MaxText, &d.MaxText},
	} {
		if *f.v <= 0 {
			*f.v = *f.d
		}
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	return l
}

// Read reads one document.
func Read(r io.Reader, lim Limits) (Log, error) {
	b := docread.NewJSON(r, lim.MaxBytes, lim.MaxDepth)
	rd := reader{b: b, lim: lim}
	log, err := rd.log()
	if err != nil {
		return Log{}, b.Refused("reading SARIF", err)
	}
	if err := b.End(); err != nil {
		return Log{}, b.Refused("reading SARIF", err)
	}
	return log, nil
}

type reader struct {
	b   *docread.JSON
	lim Limits
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
	ruleIndex  *int
	messageID  string
	arguments  []string
	hasOwnText bool
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
	rd.settle(&run, waiting)
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
func (rd *reader) settle(run *Run, waiting []pending) {
	for i := range run.Results {
		res, p := &run.Results[i], waiting[i]
		var rule *Rule
		if p.ruleIndex != nil && *p.ruleIndex >= 0 && *p.ruleIndex < len(run.Tool.Rules) {
			rule = &run.Tool.Rules[*p.ruleIndex]
			if res.RuleID == "" {
				res.RuleID = rule.ID
			}
		} else if res.RuleID != "" {
			for j := range run.Tool.Rules {
				if run.Tool.Rules[j].ID == res.RuleID {
					rule = &run.Tool.Rules[j]
					break
				}
			}
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
			res.Message = rd.text(worded(res.Message, p.messageID, p.arguments, stringsOf))
		}
	}
}

func (rd *reader) tool(run *Run) error {
	component := func(driver bool) error {
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
					rule, err := rd.rule(&run.Discarded)
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
			return component(true)
		case "extensions":
			return rd.b.Array(func() error { return component(false) })
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
				if len(rule.messages) < rd.lim.MaxRules {
					rule.messages[id] = s
				}
				return err
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
						if len(rule.Tags) < rd.lim.MaxRules {
							rule.Tags = append(rule.Tags, rd.text(s))
						}
						return err
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

// message reads a message object's text. A message with only markdown keeps
// the markdown as its text, which is shown encoded and never rendered. Where p
// is given, it records what the message cites by identifier.
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
				if p != nil && len(p.arguments) < rd.lim.MaxLocations {
					p.arguments = append(p.arguments, rd.text(s))
				}
				return err
			})
		default:
			return rd.b.Skip()
		}
	})
	if markdown != "" {
		discarded.Markdown++
		if !hasText {
			text, hasText = markdown, true
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
		case "message":
			s, err := rd.message(discarded, &p)
			res.Message = s
			return err
		case "locations", "relatedLocations":
			return rd.b.Array(func() error {
				if len(res.Locations)+len(res.Related) == rd.lim.MaxLocations {
					return over("locations in a result", rd.lim.MaxLocations)
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
				if len(res.Fingerprints) < rd.lim.MaxLocations {
					res.Fingerprints[bound.Head(scheme, docread.MostQuoted)] = rd.text(s)
				}
				return err
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
	return res, p, err
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
					if keepThread {
						res.Steps = append(res.Steps, step)
					}
					return err
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
					return rd.region(discarded, &loc, true)
				case "contextRegion":
					return rd.region(discarded, &loc, false)
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

// region reads a region's lines and columns into loc where keep is set, and
// counts the source text it carries either way.
func (rd *reader) region(discarded *Discarded, loc *Location, keep bool) error {
	return rd.b.Object(func(key string) error {
		var into *int
		switch key {
		case "startLine":
			into = &loc.StartLine
		case "startColumn":
			into = &loc.StartColumn
		case "endLine":
			into = &loc.EndLine
		case "endColumn":
			into = &loc.EndColumn
		case "snippet":
			discarded.Snippets++
			return rd.b.Skip()
		default:
			return rd.b.Skip()
		}
		n, err := rd.b.Int()
		if keep && n != nil && *n > 0 {
			*into = *n
		}
		return err
	})
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
		case "toolExecutionNotifications", "toolConfigurationNotifications":
			return rd.b.Array(func() error {
				lvl, id := "", ""
				err := rd.b.Object(func(key string) error {
					switch key {
					case "level":
						s, err := rd.b.Str()
						lvl = s
						return err
					case "descriptor", "associatedRule":
						return rd.b.Object(func(key string) error {
							if key == "id" && id == "" {
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
				if lvl == "error" {
					inv.Errors++
					if id != "" && len(inv.Notified) < rd.lim.MaxRules {
						inv.Notified = append(inv.Notified, id)
					}
				}
				return err
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
)

// properties reads one property bag, refusing one with more members than the
// bound.
func (rd *reader) properties(fn func(key string) error) error {
	n := 0
	return rd.b.Object(func(key string) error {
		n++
		if n > rd.lim.MaxProperties {
			return over("members in a property bag", rd.lim.MaxProperties)
		}
		return fn(key)
	})
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
		case propChanged:
			return rd.b.Array(func() error {
				s, err := rd.b.Str()
				if len(p.Changed) == rd.lim.MaxModules {
					return over("changed repositories in a run", rd.lim.MaxModules)
				}
				p.Changed = append(p.Changed, rd.text(s))
				return err
			})
		default:
			if strings.HasPrefix(key, "openpsirt/") {
				return refusal.Errorf("run property %q is not one this deployment reads", bound.Head(key, docread.MostQuoted))
			}
			return rd.b.Skip()
		}
	})
}
