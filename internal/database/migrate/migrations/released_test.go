// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// shipped is each migration the v0.1.0 release carried, and the digest of the
// file as that release tagged it. A database the release built has applied
// exactly these, so what they do is fixed: an edit to one changes a schema
// that deployments already hold without changing what they have recorded.
var shipped = map[string]string{
	"00001_settings.go":        "01423872c77883bbf7e51ceb6d2376d12303c6ea599df45ec2607d10a9c0353d",
	"00002_catalog.go":         "b591403765aee74ebb71b7a7e671c063b411fa1fbc9b3d865b0bee3b842d7d5b",
	"00003_scan.go":            "63f1e248784db3ef1bb13db44f0a5b91e7ab2808f4f059fd943f697b57406a23",
	"00004_job.go":             "fea3101ca8c9b912a8c3c9b3a6d6eec138b04f7885ab575122be0c23ea2c2feb",
	"00005_graph.go":           "3b2ee62f56ecfc49ad956d78962bc11f6fa74d7cd7c7bc4f2872fc56cd97d6f9",
	"00007_scan_document.go":   "798b8ca33a44a962c432b2654de1341b1eefc6a87c78dad900ed860bdf33bd5d",
	"00009_finding.go":         "84284779dfcdf41ee9d8652f36b339e41dd6dbfb2ada6eb23902ad15788165e8",
	"00010_access.go":          "83201a61620a808e637a6f48847f38b4771ffd29e96cbb278b67867be4744c6a",
	"00011_triage.go":          "e8c8a493e21868a746583ec6ca306f98dbe58a26be64a74521c528f20471e9c0",
	"00012_graph_walk.go":      "d9995b3af23c43bbd23eba22e011b47c3426e865e1fa125827ddc10e5418c133",
	"00016_assessment.go":      "e62e352f67ab648b649cc6dcaa09e8448b4b35fd2e93bb25a8e998ee914fb5c9",
	"00018_notification.go":    "883b5a55bcb85a6a8f4ed56ff9df31da3b73a44218aab5bfeb40473ca8ec5c80",
	"00019_scan_recency.go":    "cc01d8fcd28e12df96338de61f8ffeaa1e9f165c9f212729061d91a63bea9da7",
	"00020_lease.go":           "0ef30b502fe11a3d24c1eb7630f02e480dee0825458961711bd8309fce9a5785",
	"00021_upgrade.go":         "51a750d920b62e174cdad0b70b3fb0d136cc0ce76cbc39ea9611c045e1ccab9e",
	"00022_disclosure.go":      "5eb5892f8dae365e911bf7bb56b15f2ff96678ae55a04d8efd39c0778f6fad47",
	"00023_attachment.go":      "9f47f43adbe4a15be563d036ddfeef8d8860f2ff44ede4d5982230e6dc57600f",
	"00024_team.go":            "8218a69c486b8aadc0ff21755b6f6f2ce588655fa4ef23c12d9598d0f777fc9e",
	"00025_trail.go":           "7f2e032488fa597cfb71ff2791f3caaa5f96dc1a4d316ecbdba14e3f4371f531",
	"00026_saved_filter.go":    "53df2c00968f77a5b9c515a0b1755d1a1117971329101331c17639523865b680",
	"00027_vex.go":             "3d2bd606c255527a37272629cd4b102684790ea7127d8be2cb19e73e6ff575b2",
	"00028_routing.go":         "9f241642bbacb5b54b666175091fe5cd95b1a03fdebf187c50694066129b4f9b",
	"00029_collaborator.go":    "1acc3b604e3a31397e394c0fab5a5826b4133932387258a76a732096fb73ea8d",
	"00030_report.go":          "41a57330b1e135c3a4f2afd56151feda478e10a94495d4b0748527e1c9addcf5",
	"00031_issuance.go":        "9f32f2d3122d1036afbe705d80b050bd4bf6a33f5343f07ff8d4ca5f070f0c7c",
	"00033_outbound.go":        "aaaf81fef5f4e28979f37630f98fd3f2b1c827a8b06abf48ab503a3b737c11f9",
	"00034_comment_history.go": "ab6ac6946e00435e87ff827e1a3bfd2c9960c1b21f7aaa55fa90de166f1c78ea",
	"00035_tag.go":             "2043aebb9b92c1a8c3d43ef68213d338c539dc5d9bbf1adba13262728fd2c361",
	"00036_issue_note.go":      "6d33a90a70fed1060ca32d7ee68233a9d34f717493f4fb8b7ae1de7a55731a30",
}

// Every migration up to the release's last is the file the release shipped,
// below the license header added since, and every file the release shipped is
// here.
func TestTheMigrationsV010ShippedAreTheFilesItTagged(t *testing.T) {
	names, err := fs.Glob(sources, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, name := range names {
		digits, _, ok := strings.Cut(name, "_")
		version, err := strconv.Atoi(digits)
		if !ok || err != nil || version > 36 {
			continue
		}
		seen++
		want, listed := shipped[name]
		if !listed {
			t.Errorf("%s is numbered within v0.1.0's migrations and the release did not ship it", name)
			continue
		}
		content, err := sources.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		// The header is the comment block the file opens with, and a blank
		// line ends it.
		_, body, found := strings.Cut(string(content), "\n\n")
		if !found || !strings.HasPrefix(string(content), "// Copyright") {
			t.Errorf("%s does not open with the license header", name)
			continue
		}
		sum := sha256.Sum256([]byte(body))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s is not the file v0.1.0 shipped; a change to its schema goes in a later migration", name)
		}
	}
	if seen != len(shipped) {
		t.Errorf("%d of the %d migrations v0.1.0 shipped are here", seen, len(shipped))
	}
}

// shippedV020 is migration 37 and every declaration it reads, as the v0.2.0
// release tagged them. A database the release built has applied migration 37
// as these files wrote it, so a change after the tag goes in a later
// migration.
var shippedV020 = map[string]string{
	"00037_v020.go":           "f0f92960d7af25c888f9699cca48b7cba64baa88486800c18893d95d172fd651",
	"v020_advisory.go":        "ed0e2e0f2de03e6de3faa41b1e129be5586fe172684c7dc9a8a20d65e11fc6ab",
	"v020_advisory_source.go": "3ea9523f7050c68383077ccbfdea3d308428d5310bd87e6fc536a94bc69c4e0c",
	"v020_attachment.go":      "bd01b62779f62591dcc200197372cf24a9867690d9ddfcbc1a039d7b1e7f109c",
	"v020_catalog.go":         "c0f5ada8653e132862cde0e33babb282ffce2912988f298a06dbf3b912189ac5",
	"v020_disclosure.go":      "99b930f20c8afa77c83d69fb5c8e9dd2b9eff5d230a7a0a8e566e59b3aa24fb1",
	"v020_downgrade.go":       "8233e57d5a7c735486a286fe7960a9a65660828a7c0048faca4cd1c17046cdb8",
	"v020_exploited_here.go":  "b4acf0dae10298a69ed6e28fe6ecfc3860263575fd73c471522904ea3d161969",
	"v020_finding.go":         "61bd8aa3bb193324be50c2e8db5aa5fb44b50eb2f03dd1fac3cea746068ee49a",
	"v020_notification.go":    "d774c545254c78f03afbc41b185edf25d6ebd2e6549e64f86a2baa3ec2341c5c",
	"v020_patch_branch.go":    "bdd69d8939f0fd7d2120380bc0dda3800a04797703caefefa7c22deba24f1560",
	"v020_report.go":          "19e1ce04f6d8425498ec62ee519164f9d63aa96f5a780e8e4104e9df0a00b580",
	"v020_scan.go":            "786465128d186a3e3daa5e87410f3eaed9705f3a61130ff1bc6a2204822dba35",
	"v020_upgrade.go":         "94e9737a93a2c771b83bfac34334d5b2e5eda4674874ced49bac640395a2023e",
	"v020_vex.go":             "6cd2b765f2cb0b17554889a914a6c6fb8cb577f956d7e046e98d6fc078474247",
	"v020_vex_issuance.go":    "6c5c6f19ab4e715f6719d9a977293c2752399447e6f19fd6a9d68ae0580f9db5",
}

// Migration 37 and every declaration it reads are the files v0.2.0 tagged,
// and every one of those files is here.
func TestTheMigrationV020ShippedIsTheFilesItTagged(t *testing.T) {
	names, err := fs.Glob(sources, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") ||
			(!strings.HasPrefix(name, "00037_") && !strings.HasPrefix(name, "v020_")) {
			continue
		}
		seen++
		want, listed := shippedV020[name]
		if !listed {
			t.Errorf("%s belongs to migration 37 and the v0.2.0 release did not ship it", name)
			continue
		}
		content, err := sources.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		_, body, found := strings.Cut(string(content), "\n\n")
		if !found || !strings.HasPrefix(string(content), "// Copyright") {
			t.Errorf("%s does not open with the license header", name)
			continue
		}
		sum := sha256.Sum256([]byte(body))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s is not the file v0.2.0 shipped; a change to its schema goes in a later migration", name)
		}
	}
	if seen != len(shippedV020) {
		t.Errorf("%d of the %d files v0.2.0 shipped for migration 37 are here", seen, len(shippedV020))
	}
}
