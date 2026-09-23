package main

// held is every file in the tree that somebody else wrote, or that this
// project produced by running somebody else's tool, and what it may be kept
// under.
//
// A file lands here by being a fixture, by carrying somebody else's copyright
// or license statement, by saying `NOTICE` records it, or by being named in
// `NOTICE`. Each of those is found in the tree and then looked for here, so a
// file copied in without a line here fails the gate rather than waiting for a
// review to notice it.
//
// The license is what the file's source states, in the spelling SPDX gives
// it. Where no SPDX identifier exists the reference names the terms instead.
var held = []entry{
	// The SPDX examples, in both versions where there is a pair. The
	// spdx-examples repository states CC0-1.0 for its documents; the sample
	// source beside them is GPL-3.0-or-later and is not taken.
	{"internal/sbom/testdata/rust-app.spdx.json", "CC0-1.0", "https://github.com/spdx/spdx-examples"},
	{"internal/sbom/testdata/rust-app.spdx3.json", "CC0-1.0", "https://github.com/spdx/spdx-examples"},
	{"internal/sbom/testdata/maven-app.spdx.json", "CC0-1.0", "https://github.com/spdx/spdx-examples"},
	{"internal/sbom/testdata/maven-app.spdx3.json", "CC0-1.0", "https://github.com/spdx/spdx-examples"},
	{"internal/sbom/testdata/acme-app.spdx3.json", "CC0-1.0", "https://github.com/spdx/spdx-examples"},
	{"internal/sbom/testdata/appbom.spdx3.json", "CC0-1.0", "https://github.com/spdx/spdx-examples"},
	{"internal/sbom/testdata/suse-su-2026_0005-1.json", "CC-BY-4.0",
		"https://ftp.suse.com/pub/projects/security/csaf/"},

	// FIRST's reference calculator for CVSS version 4: its table of class
	// scores transcribed, and the scores it answers for a corpus of vectors.
	{"internal/finding/cvss4.go", "BSD-2-Clause", "https://github.com/FIRSTdotorg/cvss-v4-calculator"},
	{"internal/finding/testdata/cvss4-scores.txt", "BSD-2-Clause",
		"https://github.com/FIRSTdotorg/cvss-v4-calculator"},
	// Ratings as the National Vulnerability Database publishes them, a work
	// of the United States government.
	{"internal/finding/testdata/cvss4-published.txt", publicDomain, "https://nvd.nist.gov"},

	// The weakness catalog's names, generated from what MITRE publishes.
	{"internal/weakness/names.go", cweTerms, "https://cwe.mitre.org/about/termsofuse.html"},

	// Version-ordering suites, taken whole from the project defining each
	// ordering.
	{"internal/vercmp/pypi_test.go", "Apache-2.0 OR BSD-2-Clause", "https://github.com/pypa/packaging"},
	{"internal/vercmp/maven_test.go", "Apache-2.0", "https://github.com/apache/maven"},
	{"internal/vercmp/nuget_test.go", "Apache-2.0", "https://github.com/NuGet/NuGet.Client"},

	// Written here, or produced here by running a tool over something this
	// project builds or a public image. The fixture READMEs say which.
	{"internal/sbom/testdata/advisory-named-products.csaf.json", ours, ""},
	{"internal/sbom/testdata/advisory-opaque-products.csaf.json", ours, ""},
	{"internal/sbom/testdata/advisory-platform-packages.csaf.json", ours, ""},
	{"internal/sbom/testdata/advisory-recommended.csaf.json", ours, ""},
	{"internal/sbom/testdata/alpine-image.spdx.json", ours, ""},
	{"internal/sbom/testdata/build-fragment.cdx.json", ours, ""},
	{"internal/sbom/testdata/gomod-app.cdx.json", ours, ""},
	{"internal/sbom/testdata/image.cdx.json", ours, ""},
	{"internal/sbom/testdata/openpsirt-image.cdx.json", ours, ""},
	{"internal/sbom/testdata/producer-paths.txt", ours, ""},
	{"internal/sbom/testdata/suppression-from-patch.openvex.json", ours, ""},
	{"internal/sbom/testdata/switch-image.cdx.json.xz", ours, ""},
	{"internal/sbom/testdata/switch-image-mellanox.cdx.json.xz", ours, ""},
	{"internal/scanner/testdata/grype-output.json", ours, ""},
	{"internal/scanner/testdata/grype-known-exploited.json", ours, ""},
	{"testdata/xss-corpus.json", ours, ""},
	// An SPDX document written inline as a test's input, whose data license
	// is the one the format requires every document to state.
	{"internal/sbom/spdx_test.go", ours, ""},
	{"internal/httpapi/scans_test.go", ours, ""},
}
