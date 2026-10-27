// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package weblink builds the addresses into the web application that the
// server hands out: the link a notification carries, and the one a message
// sent outside the deployment ends on.
//
// Every address the server writes is built here and nowhere else. The web
// application's route table is the one definition of which addresses it
// answers and which query parameters a link may set on each; the tests in this
// package build every address with awkward values and hold each one against
// that table, and fail on an address spelled anywhere else in the server.
//
// Every part a caller supplies is escaped for where it lands: a path segment
// with url.PathEscape, a query value with url.QueryEscape. A name holding a
// slash or a question mark otherwise becomes a second segment or a query, and
// the link opens a screen about something else.
//
// A name of nothing but dots has no escaped form: a browser resolves "." and
// ".." before the request is sent, percent-encoded or not, so the link would
// climb to a different screen. An address naming one is the front page.
package weblink

import (
	"net/url"
	"strconv"
	"strings"
)

// Home is the front page, which a message about something undisclosed ends on
// in place of an address that would name it.
func Home() string { return "/" }

// ReviewQueue is the list of decisions waiting for somebody to agree to them.
func ReviewQueue() string { return "/review-queue" }

// ReviewQueueMine is the review queue opened on the decisions somebody made
// themselves, which is where a decision sent back to its author is answered.
func ReviewQueueMine() string { return "/review-queue?mine=1" }

// ReviewQueueReaffirm is the review queue opened on the decisions of somebody's
// that lapsed, which is where they are re-affirmed.
func ReviewQueueReaffirm() string { return "/review-queue?reaffirm=1" }

// Assignments is the screen of who holds what.
func Assignments() string { return "/assignments" }

// AssignmentsTeam is the assignments screen opened on one team's queue.
func AssignmentsTeam(team string) string {
	return "/assignments?tab=people&team=" + url.QueryEscape(team)
}

// AssignmentsPerson is the assignments screen opened on what one person holds.
func AssignmentsPerson(identity string) string {
	return "/assignments?tab=people&person=" + url.QueryEscape(identity)
}

// Settings is the deployment's settings.
func Settings() string { return "/settings" }

// Products is the products this deployment declares, where each one's upstream
// is reached from its row.
func Products() string { return "/products" }

// System is the deployment's own health.
func System() string { return "/system" }

// Incidents is every standing incident, with the response windows counted for
// each.
func Incidents() string { return "/incidents" }

// Decision is one decision, whole.
func Decision(id int64) string { return "/decisions/" + strconv.FormatInt(id, 10) }

// DecisionOccurrence is one occurrence of a decision, which the screen resolves
// to the decision it belongs to.
func DecisionOccurrence(id int64) string { return "/decision-occurrences/" + strconv.FormatInt(id, 10) }

// Issue is one issue, everywhere it sits.
func Issue(identifier string) string {
	if climbs(identifier) {
		return Home()
	}
	return "/issues/" + url.PathEscape(identifier)
}

// ProductFindings is a product's findings list, searched for one term.
func ProductFindings(product, search string) string {
	if climbs(product) {
		return Home()
	}
	return "/products/" + url.PathEscape(product) + "/findings?q=" + url.QueryEscape(search)
}

// VulnerabilityReportsWaiting is a product's vulnerability reports opened on
// the rulings waiting for a second person.
func VulnerabilityReportsWaiting(product string) string {
	if climbs(product) {
		return Home()
	}
	return "/products/" + url.PathEscape(product) + "/vulnerability-reports?waiting=1"
}

// VulnerabilityReport is one of a product's vulnerability reports.
func VulnerabilityReport(product, reference string) string {
	if climbs(product, reference) {
		return Home()
	}
	return "/products/" + url.PathEscape(product) + "/vulnerability-reports/" + url.PathEscape(reference)
}

// Finding is one finding: an issue at one component of one build. A version,
// where one is given, picks the component among several of that name in the
// build; empty, the address carries none.
func Finding(product, branchOrTag, variant, vulnerability, component, version string) string {
	if climbs(product, branchOrTag, variant, vulnerability, component) {
		return Home()
	}
	address := build(product, branchOrTag, variant) +
		"/findings/" + url.PathEscape(vulnerability) +
		"/components/" + url.PathEscape(component)
	if version != "" {
		address += "?version=" + url.QueryEscape(version)
	}
	return address
}

// CodeFinding is one static analysis code finding's evidence on one build.
func CodeFinding(product, branchOrTag, variant, occurrence string) string {
	if climbs(product, branchOrTag, variant, occurrence) {
		return Home()
	}
	return build(product, branchOrTag, variant) + "/code-findings/" + url.PathEscape(occurrence)
}

// CodeFindings is a product's code findings in one state on one build, and of one series
// where one is named.
func CodeFindings(product, branchOrTag, variant, state, series string) string {
	if climbs(product) {
		return Home()
	}
	query := url.Values{"state": {state}, "branch_or_tag": {branchOrTag}, "variant": {variant}}
	if series != "" {
		query.Set("series", series)
	}
	return "/products/" + url.PathEscape(product) + "/code-findings?" + query.Encode()
}

// SuppressionRules is a product's suppression rules.
func SuppressionRules(product string) string {
	if climbs(product) {
		return Home()
	}
	return "/products/" + url.PathEscape(product) + "/suppression-rules"
}

// Uploads is the list of what one build was sent.
func Uploads(product, branchOrTag, variant string) string {
	if climbs(product, branchOrTag, variant) {
		return Home()
	}
	return build(product, branchOrTag, variant) + "/uploads"
}

// InventoryChanges is what one upload moved in a build's inventory.
func InventoryChanges(product, branchOrTag, variant string, scan int64) string {
	if climbs(product, branchOrTag, variant) {
		return Home()
	}
	return build(product, branchOrTag, variant) + "/uploads/" + strconv.FormatInt(scan, 10) + "/changes"
}

// AnalyticsReport is one report under Analytics, opened on a window of days.
func AnalyticsReport(slug, days string) string {
	if climbs(slug) {
		return Home()
	}
	return "/analytics/" + url.PathEscape(slug) + "?days=" + url.QueryEscape(days)
}

// build is the prefix every address under one build shares. It is not an
// address by itself: the web application answers only the screens below it.
func build(product, branchOrTag, variant string) string {
	return "/products/" + url.PathEscape(product) +
		"/branches-and-tags/" + url.PathEscape(branchOrTag) +
		"/variants/" + url.PathEscape(variant)
}

// climbs reports whether any name would be a path segment of nothing but
// dots, which a browser resolves rather than sends.
func climbs(names ...string) bool {
	for _, name := range names {
		if name != "" && strings.Trim(name, ".") == "" {
			return true
		}
	}
	return false
}
