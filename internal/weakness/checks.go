// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness

import (
	"sort"
	"strings"
)

// clangChecks is the weaknesses each clang static analyzer checker finds,
// for the checkers that apply to C. clang tags no rule with a weakness and
// publishes no table, so this one is held here. A checker reporting more than
// one kind of flaw under one name names each: unix.Malloc reports leaks,
// double frees and uses after free. A checker mapped to nothing is one no
// weakness fits with confidence, listed so that a checker missing from the
// table is one this has not looked at.
var clangChecks = map[string][]string{
	"core.BitwiseShift":                                     {"CWE-1335"},
	"core.CallAndMessage":                                   nil,
	"core.DivideZero":                                       {"CWE-369"},
	"core.NonNullParamChecker":                              {"CWE-476"},
	"core.NullDereference":                                  {"CWE-476"},
	"core.StackAddressEscape":                               {"CWE-562"},
	"core.UndefinedBinaryOperatorResult":                    nil,
	"core.VLASize":                                          nil,
	"core.uninitialized.ArraySubscript":                     {"CWE-457"},
	"core.uninitialized.Assign":                             {"CWE-457"},
	"core.uninitialized.Branch":                             {"CWE-457"},
	"core.uninitialized.CapturedBlockVariable":              {"CWE-457"},
	"core.uninitialized.NewArraySize":                       {"CWE-457"},
	"core.uninitialized.UndefReturn":                        {"CWE-457"},
	"deadcode.DeadStores":                                   {"CWE-563"},
	"optin.core.EnumCastOutOfRange":                         nil,
	"optin.mpi.MPI-Checker":                                 nil,
	"optin.performance.GCDAntipattern":                      nil,
	"optin.performance.Padding":                             nil,
	"optin.portability.UnixAPI":                             nil,
	"security.ArrayBound":                                   {"CWE-119"},
	"security.FloatLoopCounter":                             nil,
	"security.cert.env.InvalidPtr":                          {"CWE-825"},
	"security.insecureAPI.DeprecatedOrUnsafeBufferHandling": {"CWE-676"},
	"security.insecureAPI.UncheckedReturn":                  {"CWE-252"},
	"security.insecureAPI.bcmp":                             {"CWE-477"},
	"security.insecureAPI.bcopy":                            {"CWE-477"},
	"security.insecureAPI.bzero":                            {"CWE-477"},
	"security.insecureAPI.decodeValueOfObjCType":            nil,
	"security.insecureAPI.getpw":                            {"CWE-676"},
	"security.insecureAPI.gets":                             {"CWE-242"},
	"security.insecureAPI.mkstemp":                          nil,
	"security.insecureAPI.mktemp":                           {"CWE-377"},
	"security.insecureAPI.rand":                             {"CWE-338"},
	"security.insecureAPI.strcpy":                           {"CWE-676"},
	"security.insecureAPI.vfork":                            nil,
	"unix.API":                                              nil,
	"unix.Errno":                                            nil,
	"unix.Malloc":                                           {"CWE-401", "CWE-415", "CWE-416"},
	"unix.MallocSizeof":                                     {"CWE-131"},
	"unix.MismatchedDeallocator":                            {"CWE-762"},
	"unix.StdCLibraryFunctions":                             nil,
	"unix.Vfork":                                            nil,
	"unix.cstring.BadSizeArg":                               nil,
	"unix.cstring.NullArg":                                  {"CWE-476"},
	"valist.CopyToSelf":                                     nil,
	"valist.Uninitialized":                                  {"CWE-457"},
	"valist.Unterminated":                                   nil,
}

// clangTidyAnalyzer is the prefix clang-tidy puts on a static analyzer
// checker's name.
const clangTidyAnalyzer = "clang-analyzer-"

// OfRule is the weaknesses this holds for an analyzer's rule, by the name it
// is filed under: the tool's name in lower case, a slash, and the rule. It
// answers for cppcheck, clang, and the clang checkers clang-tidy runs, and is
// empty for every other rule.
func OfRule(name string) []string {
	tool, rule, ok := strings.Cut(name, "/")
	if !ok {
		return nil
	}
	var out []string
	switch tool {
	case "cppcheck":
		if cwe, ok := cppcheckChecks[rule]; ok {
			out = []string{cwe}
		}
	case "clang":
		out = clangChecks[rule]
	case "clang-tidy":
		if checker, ok := strings.CutPrefix(rule, clangTidyAnalyzer); ok {
			out = clangChecks[checker]
		}
	}
	out = append([]string(nil), out...)
	sort.Strings(out)
	return out
}

// ClangCheckers is every checker the clang table has looked at, mapped to a
// weakness or not.
func ClangCheckers() []string {
	out := make([]string, 0, len(clangChecks))
	for checker := range clangChecks {
		out = append(out, checker)
	}
	sort.Strings(out)
	return out
}
