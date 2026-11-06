// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// BurndownQuery is what a burndown and its file are asked with: the scope, day
// 0, a severity, and the subtree trend's narrowings with a package identifier
// prefix beside the name.
type BurndownQuery struct {
	core.ScopeQuery
	Since     string      `query:"since" format:"date" doc:"Day 0, as a date. Absent, the day the earliest finding in the selection opened. A day 0 more than 729 days back is moved to 729 days back, so at most 730 days are drawn, today included. A day after today is refused"`
	Severity  core.Rating `query:"severity" doc:"The least severe band kept: high keeps critical and high. An unrated issue reads as medium"`
	Component string      `query:"component" doc:"Keep only what is open against components of this name, whatever version"`
	Purl      string      `query:"purl" doc:"Keep only what is open against components whose package identifier this prefix chooses, whatever version and qualifiers: a package such as pkg:github/sonic-net/sonic-swss, or everything under a path ending in a slash such as pkg:github/sonic-net/. Without the slash it is that package alone. Matched without regard to capitals. A prefix that does not start with pkg: and a type is refused"`
	Beneath   string      `query:"beneath" doc:"Keep only what sits at this component or anywhere under it. A subtree is a walk over one build's edges, so this needs a product, a branch and a variant naming exactly one build. A name the build does not hold answers 404, and one it holds as more than one component answers 409 naming the choices"`
	Version   string      `query:"beneath_version" doc:"The version, where the build holds that name at several"`
	Ecosystem string      `query:"beneath_ecosystem" doc:"The ecosystem, for the few names a build holds at one version as two components"`
	Namespace string      `query:"beneath_namespace" doc:"The namespace, for the few names a build holds at one version in one ecosystem as two components"`
	Package   string      `query:"beneath_purl" maxLength:"512" doc:"Keep only what sits at a component of this package, at any version the build ships it, or anywhere under one: a repository shipped at several commits, such as pkg:github/sonic-net/sonic-swss. A finding under two of them counts once. Not with beneath. A subtree is a walk over one build's edges, so this needs a product, a branch and a variant naming exactly one build. A package the build does not hold answers 404; a path ending in a slash, and a package the build holds as more than 20 components, are refused"`
}

// burndownAsked is a burndown query read: day 0, the narrowing and the scope,
// each refused before anything is counted.
type burndownAsked struct {
	subject access.Subject
	since   time.Time
	scope   finding.Scope
	within  finding.Within
}

// read authorizes the request and resolves what it names, in that order: the
// scope first, so a component is looked up only in a build the caller may
// read.
func (q BurndownQuery) read(ctx context.Context, in core.Deps) (*burndownAsked, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return nil, err
	}
	out := &burndownAsked{subject: subject}
	if q.Since != "" {
		day, err := time.Parse(time.DateOnly, q.Since)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity("since is a date, written as 2026-03-31")
		}
		if day.After(time.Now().UTC()) {
			return nil, huma.Error422UnprocessableEntity("since is day 0, which is today or earlier")
		}
		out.since = day
	}
	var prefix graph.PurlPrefix
	if strings.TrimSpace(q.Purl) != "" {
		if prefix = graph.ParsePurlPrefix(q.Purl); prefix.Empty() {
			return nil, huma.Error422UnprocessableEntity(
				"purl is a package identifier prefix, such as pkg:github/sonic-net/ or pkg:deb/debian/curl")
		}
	}
	if out.scope, err = core.Scoped(ctx, in, subject, q.ScopeQuery); err != nil {
		return nil, err
	}
	beneath, err := core.BeneathStarts(ctx, in, out.scope, q.Beneath, graph.Choice{
		Version: q.Version, Ecosystem: q.Ecosystem, Namespace: q.Namespace,
	}, q.Package)
	if err != nil {
		return nil, err
	}
	out.within = finding.Within{Component: q.Component, Purl: prefix, Beneath: beneath}
	return out, nil
}

// BurnPointBody is one day of a burndown.
type BurnPointBody struct {
	At         string         `json:"at" format:"date" doc:"The day, which ends at midnight UTC after it"`
	Left       int            `json:"left" doc:"Issues at components open at the end of the day and not answered by a dismissal in force"`
	BySeverity map[string]int `json:"left_by_severity" doc:"Left, split by the severity each held"`
	New        int            `json:"new" doc:"Issues at components left for the first time, other than through a build's first scan"`
	Returned   int            `json:"returned" doc:"Issues at components back after having been in the selection before, a dismissal that lapsed or was withdrawn included"`
	Fixed      int            `json:"fixed" doc:"Issues at components that left by a fix and have not been left since"`
	Dismissed  int            `json:"dismissed" doc:"Issues at components a dismissal in force answered, or a publisher stated are not affected, and that have not been left since"`
	Restored   int            `json:"restored" doc:"Issues at components back after an upload removed them that moved a sharp share of its build's inventory. A mark, in no other count"`
	Baseline   int            `json:"baseline" doc:"Issues at components a build's first scan brought. A mark, in no other count"`
	FirstScans int            `json:"first_scans" doc:"Builds whose first scan was on the day"`
}

// ProjectionBody is where the recent pace takes what is left.
type ProjectionBody struct {
	Days       int     `json:"days" doc:"The latest days the pace is read over: 14, or every day where fewer are drawn"`
	Done       int     `json:"done" doc:"Fixed and dismissed over those days"`
	Added      int     `json:"added" doc:"New and returned over those days"`
	PerDay     float64 `json:"per_day" doc:"Done less added, a day. Zero or below is a backlog not converging"`
	Converging bool    `json:"converging" doc:"Whether done outran added over those days"`
	ZeroOn     string  `json:"zero_on,omitempty" format:"date" doc:"The day what is left reaches zero at that pace. Absent where it does not converge, or would take more than ten years"`
}

// ChosenBody is one package a name or a prefix chose.
type ChosenBody struct {
	Package   string `json:"package" doc:"The package identifier with version and qualifiers cut, or the name where the component has none"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The package identifier's type"`
	Name      string `json:"name" doc:"The component's name, folded for capitals"`
}

// BurndownBody is a burndown.
type BurndownBody struct {
	Since      string          `json:"since" format:"date" doc:"Day 0, as used"`
	Start      int             `json:"start" doc:"Left at the start of day 0"`
	Points     []BurnPointBody `json:"points"`
	Projection ProjectionBody  `json:"projection"`
	Chosen     []ChosenBody    `json:"chosen" doc:"The packages a component name or a purl prefix chose, with the ecosystem each is in, at most 20. Empty where neither was sent"`
	MoreChosen bool            `json:"more_chosen" doc:"Whether the name or prefix chose more packages than chosen lists"`
}

func burndownBody(b *finding.Burndown) BurndownBody {
	out := BurndownBody{
		Since: b.Since.UTC().Format(time.DateOnly), Start: b.Start,
		Points: make([]BurnPointBody, 0, len(b.Points)),
		Chosen: make([]ChosenBody, 0, len(b.Chosen)), MoreChosen: b.MoreChosen,
		Projection: ProjectionBody{
			Days: b.Ahead.Days, Done: b.Ahead.Done, Added: b.Ahead.Added,
			PerDay: b.Ahead.PerDay, Converging: b.Ahead.Converging,
		},
	}
	if b.Ahead.ZeroOn != nil {
		out.Projection.ZeroOn = b.Ahead.ZeroOn.UTC().Format(time.DateOnly)
	}
	for _, p := range b.Points {
		out.Points = append(out.Points, BurnPointBody{
			At: core.LastDay(p.At), Left: p.Left, BySeverity: p.BySeverity, New: p.New, Returned: p.Returned,
			Fixed: p.Fixed, Dismissed: p.Dismissed, Restored: p.Restored, Baseline: p.Baseline,
			FirstScans: p.FirstScans,
		})
	}
	for _, c := range b.Chosen {
		out.Chosen = append(out.Chosen, ChosenBody{Package: c.Package, Ecosystem: c.Ecosystem, Name: c.Name})
	}
	return out
}

// burndownSays is what the burndown and its file say they count.
const burndownSays = "Each count is of an issue at a component, as the trend counts. `left` is open " +
	"and not answered by a dismissal in force: not applicable, wrong match, will not fix or " +
	"already fixed, agreed by a second person or needing none. `fixed` and `dismissed` pull it " +
	"down, a statement by a supplier or an upstream that it is not affected counting as " +
	"dismissed; `new` and `returned` push it up, and a dismissal that lapses or is withdrawn " +
	"is returned. A deferral, a planned upgrade and a waiting proposal answer nothing. " +
	"`restored` and `baseline` are marks in no other count."

func registerBurndown(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-burndown", Method: http.MethodGet, Path: "/v1/burndown",
		Summary: "Show the findings burndown",
		Description: "Returns, for each day from day 0 through today, the issues left at its end " +
			"and the issues that moved in it, with what was left at day 0's start and where the " +
			"latest 14 days' pace takes the line.\n\n" + burndownSays + "\n\n" +
			"Narrowable as the trend is, and also by `purl`, a package identifier prefix, and by " +
			"`severity`. `chosen` names the packages a name or a prefix matched, so a name two " +
			"ecosystems share can be told apart.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *BurndownQuery) (*struct {
		Body BurndownBody
	}, error) {
		asked, err := input.read(ctx, in)
		if err != nil {
			return nil, err
		}
		b, err := finding.NewStore(in.DB.DB).Burndown(ctx, asked.subject, asked.scope, asked.since,
			string(input.Severity), asked.within)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the burndown could not be worked out", err)
		}
		return &struct{ Body BurndownBody }{Body: burndownBody(b)}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-burndown", Method: http.MethodGet, Path: "/v1/burndown.{format}",
		Summary: "Export the findings burndown",
		Description: "One row per day from day 0, with what was left at its end, split by " +
			"severity, what moved in it, and the running totals of added and done since day 0. " +
			"The counts are the burndown's.\n\n" + burndownSays + "\n\n" +
			"Takes the burndown's parameters. Read with your own visibility, like the chart it " +
			"comes from.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		BurndownQuery
	}) (*huma.StreamResponse, error) {
		// Read, and the burndown worked out, before the file is begun, so a
		// refusal or a failure is a status rather than a file cut short, and
		// the file states the day 0 that was used.
		asked, err := input.read(ctx, in)
		if err != nil {
			return nil, err
		}
		bands := append(finding.Bands(), finding.Unrated)
		header := []string{"day", "left", "new", "returned", "fixed", "dismissed", "returned after a gap",
			"baseline", "first scans", "added since day 0", "done since day 0"}
		for _, band := range bands {
			header = append(header, "left "+band)
		}
		b, err := finding.NewStore(in.DB.DB).Burndown(ctx, asked.subject, asked.scope, asked.since,
			string(input.Severity), asked.within)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the burndown could not be worked out", err)
		}
		used := b.Since.UTC().Format(time.DateOnly)
		day0 := used
		switch {
		case input.Since == "":
			day0 = used + ", the day the earliest finding opened"
		case input.Since != used:
			day0 = used + ", moved from " + input.Since
		}
		about := []core.Stated{{Label: "day 0", Value: day0}, {Label: "left at day 0's start", Value: strconv.Itoa(b.Start)}}
		if input.Severity != "" {
			about = append(about, core.Stated{Label: "severity", Value: string(input.Severity) + " and worse"})
		}
		if input.Purl != "" {
			about = append(about, core.Stated{Label: "purl", Value: input.Purl})
		}
		out := core.Exporting{
			What:   "the findings burndown",
			About:  about,
			Header: header,
			// Every day in one answer: a burndown is worked out over the whole
			// window, so there is no offset that means anything.
			Rows: func(_ context.Context, _, offset int) ([][]string, error) {
				if offset > 0 {
					return nil, nil
				}
				rows := make([][]string, 0, len(b.Points))
				added, done := 0, 0
				for _, p := range b.Points {
					added += p.New + p.Returned
					done += p.Fixed + p.Dismissed
					row := []string{
						core.LastDay(p.At), strconv.Itoa(p.Left), strconv.Itoa(p.New), strconv.Itoa(p.Returned),
						strconv.Itoa(p.Fixed), strconv.Itoa(p.Dismissed), strconv.Itoa(p.Restored),
						strconv.Itoa(p.Baseline), strconv.Itoa(p.FirstScans), strconv.Itoa(added), strconv.Itoa(done),
					}
					for _, band := range bands {
						row = append(row, strconv.Itoa(p.BySeverity[band]))
					}
					rows = append(rows, row)
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, "burndown", out)
		}}, nil
	})
}
