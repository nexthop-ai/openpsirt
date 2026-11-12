// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// TrendQuery is what the backlog trend and its file are asked with: the
// scope, the steps, and the narrowings to a component or a subtree.
type TrendQuery struct {
	core.ScopeQuery
	core.Steps
	Component string `query:"component" doc:"Keep only what is open against components of this name, whatever version"`
	core.Subtree
}

// trendAsked is a trend query read: the window and what it narrows to, each
// refused before anything is counted.
type trendAsked struct {
	subject access.Subject
	scope   finding.Scope
	since   time.Time
	step    time.Duration
	steps   int
	within  finding.Within
}

// read authorizes the request and resolves what it names, in that order: the
// scope first, so a component is looked up only in a build the caller may
// read.
func (q TrendQuery) read(ctx context.Context, in core.Deps) (*trendAsked, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return nil, err
	}
	out := &trendAsked{subject: subject}
	if out.since, out.step, out.steps, err = q.Window(time.Now()); err != nil {
		return nil, err
	}
	if out.scope, err = core.Scoped(ctx, in, subject, q.ScopeQuery); err != nil {
		return nil, err
	}
	beneath, err := q.Starts(ctx, in, out.scope)
	if err != nil {
		return nil, err
	}
	out.within = finding.Within{Component: q.Component, Beneath: beneath}
	return out, nil
}

// points is the trend the query asks for.
func (a *trendAsked) points(ctx context.Context, in core.Deps) ([]finding.Point, error) {
	return finding.NewStore(in.DB.DB).Trend(ctx, a.subject, a.scope, a.since, a.step, a.steps, a.within)
}
