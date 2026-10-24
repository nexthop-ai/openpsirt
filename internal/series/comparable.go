// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series

// Reason is why a run's absences are not evidence. A run that is not
// comparable adds and updates results and marks none not reproduced.
type Reason string

const (
	// ExitStatus is a tool that exited with a status other than zero.
	ExitStatus Reason = "exit-status"
	// Incomplete is a tool that said it did not finish.
	Incomplete Reason = "incomplete"
	// FailureSignal is a tool that reported a failure of its own run: an
	// error notification, or a result saying a unit could not be read.
	FailureSignal Reason = "failure-signal"
	// NoCoverage is a run that states neither how many units it covered nor
	// which rules it ran. Nothing tells it apart from a run of nothing.
	NoCoverage Reason = "no-coverage"
	// UnitsShort is a run that analyzed fewer units than it was meant to.
	UnitsShort Reason = "units-short"
	// ToolChanged is a tool version other than the previous run's.
	ToolChanged Reason = "tool-changed"
	// RulesChanged is a rule set other than the previous run's.
	RulesChanged Reason = "rules-changed"
)

// Reasons is every reason a run is not comparable, in the order they are
// asked.
func Reasons() []Reason {
	return []Reason{ExitStatus, Incomplete, FailureSignal, NoCoverage, UnitsShort, ToolChanged, RulesChanged}
}

// Comparability says whether a run's absences are evidence, and the first
// reason they are not. previous is the newest run of the same series applied
// to the same build, nil where there is none; signals is how many failures of
// its own run the tool reported.
func Comparability(p Params, previous *Run, signals int) (bool, Reason) {
	switch {
	case p.ExitStatus != nil && *p.ExitStatus != 0:
		return false, ExitStatus
	case p.Completed != nil && !*p.Completed:
		return false, Incomplete
	case signals > 0:
		return false, FailureSignal
	}
	units := p.UnitsExpected != nil && p.UnitsAnalyzed != nil
	if !units && p.RulesCount == nil {
		return false, NoCoverage
	}
	if units && *p.UnitsAnalyzed < *p.UnitsExpected {
		return false, UnitsShort
	}
	if previous == nil {
		return true, ""
	}
	if previous.ToolName != p.ToolName || previous.ToolVersion != p.ToolVersion {
		return false, ToolChanged
	}
	if previous.RulesDigest != p.RulesDigest {
		return false, RulesChanged
	}
	return true, ""
}
