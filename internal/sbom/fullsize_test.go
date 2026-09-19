package sbom_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// openFullSize decompresses the full-size fixture.
//
// Kept compressed in the repository: the shape is what matters and twenty
// megabytes of it in every checkout is not.
func openFullSize(t *testing.T) *os.File {
	t.Helper()
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz is not available, so the full-size fixture cannot be read here")
	}

	// Opened relative to a directory this test made, so the name cannot reach
	// outside it however this file is later edited.
	dir, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })

	const name = "switch-image.cdx.json"
	out, err := dir.Create(name)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("xz", "--decompress", "--stdout", "testdata/switch-image.cdx.json.xz")
	cmd.Stdout = out
	runErr := cmd.Run()
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("decompress the fixture: %v", runErr)
	}

	f, err := dir.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestARealImageReadsAsOneComponentPerPackage(t *testing.T) {
	// The fixture is a public switch operating-system image, and it spells
	// some packages twice: a build that merges two sources emits one package
	// with an architecture, a distribution and a source-package qualifier, and
	// the same package with only an architecture — sometimes disagreeing about
	// the architecture, and escaping the version differently.
	//
	// Taking a producer's identifier verbatim makes each spelling a component
	// of its own, which double-counts the package, splits its findings, and
	// gives half of them no vulnerability-database identifier.
	f := openFullSize(t)

	snapshot, err := sbom.Read(f, sbom.Limits{})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}

	identities := map[string]graph.Described{}
	for _, component := range snapshot.Components {
		identities[component.Identity()] = component
	}

	// Measured against this image when the fixture was taken. The document
	// describes 6,866 components and they name 6,866 packages — the reader
	// collapses nothing, because there is nothing left to collapse.
	//
	// The count is the only assertion in this file that moves. What a package
	// says it was built from and what identifier a scanner matches on are
	// checked rather than assumed, and the three constants further down hold
	// across every revision of the fixture so far.
	//
	// The earlier counts, and where they went. The document described 7,693,
	// then 7,035,
	// then 6,845, and each drop is the producer being fixed. The 658 that went
	// first are the build container's own toolchain — Go and Rust dependencies
	// harvested from `usr/` and `root/.cargo` trees inside the build slaves,
	// which the image does not ship. The 190 that went next are lockfile
	// entries under source trees this image does not build at all. Both are
	// still in the document, moved to `formulation`, which is where CycloneDX
	// puts how a thing was built: the data stays answerable for a build-chain
	// question and stops being scanned as though it shipped. Marking them
	// `scope: excluded` instead is correct for a human and inert for the
	// scanner, which ignores scope entirely.
	//
	// Nothing in this fixture is merged by name. An earlier revision spelled
	// 516 packages twice, under two package-URL namespaces for one .deb, and
	// the generator now merges them at the source (sonic-buildimage #29237).
	// So the two assertions below prove a narrower thing than the merge: that
	// this fixture arrives as one component per package, and that the reader
	// adds no duplicates of its own. The merge itself is proved by
	// TestTwoSpellingsOfOnePackageAreOneComponent below, which constructs the
	// duplicates rather than depending on a fixture to contain them — which is
	// where a rule of this kind belongs, because a fixture is somebody else's
	// output and can stop exercising it without anybody deciding to.
	//
	// The number is written down rather than expressed as a tolerance: a
	// change in it is a change in what identity means, and that is something
	// to look at rather than absorb. It has earned that twice. 6,845 became
	// 6,854 when the generator started describing the programs in the image,
	// by the number of
	// distinct program names rather than the number of programs — 13 programs
	// under 9 names — because a program arrives with no version and no package
	// identifier, and identity is a name and a version. 6,854 became 6,866 on
	// the next build for the same reason: 21 programs under 21 names, twelve
	// more than before, as the image began describing the containerd shims and
	// `ctr`, and the gNMI, gNOI and telemetry binaries in the gnmi container.
	// Twelve Go modules that had no consumer at all now hang off one of them.
	//
	// Two programs of one name still collapse into one component, and the fix
	// is not available here: the only field free to tell them apart is
	// `version`, where a scope name is a lie every consumer has to know to
	// ignore, and the honest fix is a hash on the program component. This
	// fixture no longer contains a case of it — the otel container shipped its
	// own `dockerd`, `containerd` and `runc` and no longer does — and the next
	// build can bring one back.
	const packages = 6866
	if len(snapshot.Components) != packages {
		t.Errorf("the image read as %d components, expected %d — has the fixture or the rule changed?",
			len(snapshot.Components), packages)
	}
	if len(identities) != len(snapshot.Components) {
		t.Errorf("%d components share %d identities, so the reader kept a duplicate",
			len(snapshot.Components), len(identities))
	}
}

func TestTwoSpellingsOfOnePackageAreOneComponent(t *testing.T) {
	// The shapes a merged inventory produces, side by side. The first two are
	// lifted from the fixture and differ in the ways it actually differs — an
	// escaped version against a plain one, and two sources disagreeing about
	// the architecture. The third is constructed, and says so.
	for _, c := range []struct {
		what  string
		one   string
		other string
	}{
		{
			"an escaped version against a plain one",
			"pkg:deb/debian/acl@2.3.2-2%2Bb1?arch=amd64&distro=debian-13&upstream=acl%402.3.2-2",
			"pkg:deb/debian/acl@2.3.2-2+b1?arch=amd64",
		},
		{
			"sources that disagree about the architecture",
			"pkg:deb/debian/adduser@3.152?arch=all&distro=debian-13",
			"pkg:deb/debian/adduser@3.152?arch=amd64",
		},
		{
			// Constructed rather than lifted: this producer is consistent
			// about case. The specification calls the type case-insensitive,
			// so two producers can disagree where one does not.
			"a type spelled in two cases",
			"pkg:DEB/debian/apparmor@4.1.0-1",
			"pkg:deb/debian/apparmor@4.1.0-1?arch=amd64",
		},
	} {
		one := graph.Described{Purl: c.one, Name: "x", Version: "1"}
		other := graph.Described{Purl: c.other, Name: "x", Version: "1"}
		if one.Identity() != other.Identity() {
			t.Errorf("%s: read as two components\n  %s\n  %s", c.what, c.one, c.other)
		}
	}
}

func TestPackagesThatDifferAreStillTwoComponents(t *testing.T) {
	// The other direction, which is what stops the reduction above being a
	// reduction to nothing. A version, a name, a namespace and an ecosystem
	// each still separate two packages.
	base := "pkg:deb/debian/acl@2.3.2-2"
	for _, other := range []string{
		"pkg:deb/debian/acl@2.3.2-3",
		"pkg:deb/debian/acl2@2.3.2-2",
		"pkg:deb/ubuntu/acl@2.3.2-2",
		"pkg:rpm/debian/acl@2.3.2-2",
	} {
		one := graph.Described{Purl: base}
		two := graph.Described{Purl: other}
		if one.Identity() == two.Identity() {
			t.Errorf("%s and %s read as one component", base, other)
		}
	}
}

func TestIdentityIsReadTheSameWayWhateverEmittedIt(t *testing.T) {
	// Nothing here knows which producer wrote an identifier, and it must not:
	// the inventories this will be given come from build systems nobody has
	// seen yet. So the reduction is the one the identifier specification
	// describes — decode what is escaped, lowercase what is case-insensitive,
	// and keep the parts that say which package this is — and it is applied
	// the same way to every ecosystem.
	same := []struct {
		what  string
		one   string
		other string
	}{
		{"an operating-system package", "pkg:deb/debian/curl@7.88.1-10%2Bdeb12u5?arch=amd64", "pkg:deb/debian/curl@7.88.1-10+deb12u5"},
		{"an rpm with a distribution tag", "pkg:rpm/redhat/openssl@3.0.7-24?arch=x86_64&distro=rhel-9", "pkg:rpm/redhat/openssl@3.0.7-24"},
		{"a node package", "pkg:npm/lodash@4.17.21?vcs_url=git%2Bhttps://github.com/lodash/lodash", "pkg:npm/lodash@4.17.21"},
		{"a python package", "pkg:pypi/django@4.2.1?file_name=Django-4.2.1-py3-none-any.whl", "pkg:pypi/django@4.2.1"},
		{"a go module", "pkg:golang/github.com/gin-gonic/gin@v1.9.1?go-version=1.21", "pkg:golang/github.com/gin-gonic/gin@v1.9.1"},
		{"a container image", "pkg:oci/alpine@sha256%3Aabc?repository_url=docker.io/library/alpine", "pkg:oci/alpine@sha256:abc"},
		{"an ecosystem spelled in two cases", "pkg:NPM/lodash@4.17.21", "pkg:npm/lodash@4.17.21"},
	}
	for _, c := range same {
		if (graph.Described{Purl: c.one}).Identity() != (graph.Described{Purl: c.other}).Identity() {
			t.Errorf("%s: read as two components\n  %s\n  %s", c.what, c.one, c.other)
		}
	}

	differ := []struct {
		what  string
		one   string
		other string
	}{
		{"two versions", "pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.20"},
		{"two names", "pkg:npm/lodash@4.17.21", "pkg:npm/lodash-es@4.17.21"},
		{"two namespaces", "pkg:npm/%40scope/pkg@1.0.0", "pkg:npm/%40other/pkg@1.0.0"},
		{"two ecosystems", "pkg:npm/lodash@4.17.21", "pkg:pypi/lodash@4.17.21"},
		{"a name that differs only in case", "pkg:pypi/Django@4.2.1", "pkg:pypi/django@4.2.1"},
	}
	for _, c := range differ {
		if (graph.Described{Purl: c.one}).Identity() == (graph.Described{Purl: c.other}).Identity() {
			t.Errorf("%s: read as one component\n  %s\n  %s", c.what, c.one, c.other)
		}
	}
}

func TestAComponentWithNoIdentifierIsStillIdentified(t *testing.T) {
	// Plenty of producers emit none. Name and version stand in, and two
	// components that agree on both are one.
	one := graph.Described{Name: "libfoo", Version: "1.2.3"}
	two := graph.Described{Name: "libfoo", Version: "1.2.3"}
	if one.Identity() != two.Identity() {
		t.Error("two identical components with no identifier read as two")
	}
	if (graph.Described{Name: "libfoo", Version: "1.2.4"}).Identity() == one.Identity() {
		t.Error("two versions with no identifier read as one")
	}
	// And an identifier always wins over the name, so a producer that emits
	// both cannot be split by disagreeing with itself about the name.
	withID := graph.Described{Purl: "pkg:deb/debian/libfoo@1.2.3", Name: "libfoo", Version: "1.2.3"}
	renamed := graph.Described{Purl: "pkg:deb/debian/libfoo@1.2.3", Name: "libfoo-runtime", Version: "1.2.3"}
	if withID.Identity() != renamed.Identity() {
		t.Error("one identifier read as two components because the names differed")
	}
}

func TestWhatAPackageWasBuiltFromIsReadHoweverItIsStated(t *testing.T) {
	// A shipped package usually carries a version of its own while the
	// vulnerability lives on what it was built from, so this is what explains
	// a finding and what expiry compares. It is also the name a build's own
	// suppressions use, because a patch is written against a source tree and
	// not against the binaries cut from it.
	//
	// Producers state it two ways. The format has a place for it, and several
	// producers hang it off the identifier instead. In this image 30 state it
	// the first way and 537 the second, 16 of them both, so reading only the
	// format's own mechanism captures 30 of the 551 that say anything — a
	// twentieth of what is there.
	//
	// The counts below are asserted; this sentence is not computed from
	// anything, so it is a claim about the fixture that goes stale silently
	// when the fixture moves under it.
	f := openFullSize(t)
	snapshot, err := sbom.Read(f, sbom.Limits{})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}

	var named, versioned, identified int
	for _, component := range snapshot.Components {
		if component.UpstreamName != "" {
			named++
		}
		if component.UpstreamVersion != "" {
			versioned++
		}
		if component.CPE != "" {
			identified++
		}
	}

	// Fewer than the previous fixture states, and not because anything is
	// lost: 565 becomes 551 where the generator stops describing one package
	// as two components. A pair with a pedigree on one half and an
	// `upstream=` qualifier on the other counts twice; merged, it is one
	// component carrying both and counted once. Checked rather than assumed:
	// no package states an upstream that stated none before, and 548 distinct
	// packages state one against 547.
	const (
		upstreams = 551  // every component that states one, either way
		versions  = 106  // those stating a version with it
		cpes      = 6567 // every component the document gives one
	)
	if named != upstreams {
		t.Errorf("%d components say what they were built from, expected %d", named, upstreams)
	}
	if versioned != versions {
		t.Errorf("%d say which version they were built from, expected %d", versioned, versions)
	}
	// The identifier a scanner matches on. The generator now promotes it onto
	// the surviving record when it merges a pair, so this counts what arrived
	// rather than what this reader rescued — two more than before, because the
	// merge key gained the ecosystem and stopped collapsing a Rust crate into
	// the Debian package built from it.
	if identified != cpes {
		t.Errorf("%d components kept a vulnerability-database identifier, expected %d",
			identified, cpes)
	}
}
