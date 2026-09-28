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
package weblink

import (
	"net/url"
	"strconv"
)

// Home is the front page, which a message about something undisclosed ends on
// in place of an address that would name it.
func Home() string { return "/" }

// ReviewQueue is the list of claims waiting for somebody to agree to them.
func ReviewQueue() string { return "/review-queue" }

// ReviewQueueMine is the review queue opened on the claims somebody made
// themselves, which is where a claim sent back to its author is answered.
func ReviewQueueMine() string { return "/review-queue?mine=1" }

// ReviewQueueReaffirm is the review queue opened on the claims of somebody's
// that lapsed, which is where they are re-affirmed.
func ReviewQueueReaffirm() string { return "/review-queue?reaffirm=1" }

// Work is the screen of who holds what.
func Work() string { return "/work" }

// WorkTeam is the work screen opened on one team's queue.
func WorkTeam(team string) string {
	return "/work?tab=people&team=" + url.QueryEscape(team)
}

// WorkPerson is the work screen opened on what one person holds.
func WorkPerson(identity string) string {
	return "/work?tab=people&person=" + url.QueryEscape(identity)
}

// Settings is the deployment's settings.
func Settings() string { return "/settings" }

// System is the deployment's own health.
func System() string { return "/system" }

// Obligations is the list of what the deployment owes somebody by a date.
func Obligations() string { return "/obligations" }

// Claim is one claim, whole.
func Claim(id int64) string { return "/claims/" + strconv.FormatInt(id, 10) }

// Decision is one decision, which the screen resolves to the claim it belongs
// to.
func Decision(id int64) string { return "/decisions/" + strconv.FormatInt(id, 10) }

// Issue is one issue, everywhere it sits.
func Issue(identifier string) string { return "/issues/" + url.PathEscape(identifier) }

// ProductFindings is a product's findings list, searched for one term.
func ProductFindings(product, search string) string {
	return "/products/" + url.PathEscape(product) + "/findings?q=" + url.QueryEscape(search)
}

// InboxWaiting is a product's inbox opened on the rulings waiting for a second
// person.
func InboxWaiting(product string) string {
	return "/products/" + url.PathEscape(product) + "/inbox?waiting=1"
}

// InboxReport is one report in a product's inbox.
func InboxReport(product, reference string) string {
	return "/products/" + url.PathEscape(product) + "/inbox/" + url.PathEscape(reference)
}

// Finding is one finding: an issue at one component of one build. A version,
// where one is given, picks the component among several of that name in the
// build; empty, the address carries none.
func Finding(product, stream, variant, vulnerability, component, version string) string {
	address := build(product, stream, variant) +
		"/findings/" + url.PathEscape(vulnerability) +
		"/components/" + url.PathEscape(component)
	if version != "" {
		address += "?version=" + url.QueryEscape(version)
	}
	return address
}

// Inventories is the list of what one build sent.
func Inventories(product, stream, variant string) string {
	return build(product, stream, variant) + "/scans"
}

// InventoryChanges is what one upload moved in a build's inventory.
func InventoryChanges(product, stream, variant string, scan int64) string {
	return build(product, stream, variant) + "/scans/" + strconv.FormatInt(scan, 10) + "/changes"
}

// Report is one report sheet, opened on a window of days.
func Report(slug, days string) string {
	return "/reports/" + url.PathEscape(slug) + "?days=" + url.QueryEscape(days)
}

// build is the prefix every address under one build shares. It is not an
// address by itself: the web application answers only the screens below it.
func build(product, stream, variant string) string {
	return "/products/" + url.PathEscape(product) +
		"/streams/" + url.PathEscape(stream) +
		"/variants/" + url.PathEscape(variant)
}
