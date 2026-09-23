// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestAMessageAboutSomethingUndisclosedSaysOnlyThatThereIsSomething(t *testing.T) {
	// A message cannot re-check its reader: it sits on a mail server this
	// deployment does not run, in an inbox, in a phone's lock screen, and
	// in whatever it is forwarded to. So an alert about a flaw nobody has
	// announced is itself the announcement unless it says nothing.
	//
	// The body here is the one the notification area shows, which names
	// everything — that is what makes this worth pinning: the detail
	// exists and must not travel.
	n := Notification{
		Kind:    DisclosureDue,
		Private: true,
		Body: "SONIC-2026-0001 in sonic reached its disclosure date on 2026-09-04 " +
			"and nothing has been decided.",
		Link: "/products/sonic/streams/master/variants/broadcom/findings/SONIC-2026-0001/components/swss",
	}
	got := Compose(n, "https://psirt.example")

	for _, leaked := range []string{
		"SONIC-2026-0001", "sonic", "swss", "2026-09-04", "disclosure date",
	} {
		if strings.Contains(got.Text, leaked) {
			t.Errorf("the message carries %q, which is the announcement it exists to avoid:\n%s",
				leaked, got.Text)
		}
		if strings.Contains(got.Subject, leaked) {
			t.Errorf("the subject carries %q, and a preview shows a subject without "+
				"anybody opening anything: %q", leaked, got.Subject)
		}
	}
	// The way in is the message, and it is the front door rather than the
	// finding: a path naming the identifier and the component announces both
	// to every server the message crosses, whatever the body withheld.
	if !strings.Contains(got.Text, "https://psirt.example/\n") {
		t.Errorf("the message carries no way in:\n%s", got.Text)
	}
	if strings.Contains(got.Text, "/findings/") {
		t.Errorf("the address names the finding, which the body was careful not to:\n%s", got.Text)
	}
	// The same address a channel carries in a field of its own. A webhook
	// body puts the link somewhere a reader does not have to open the text to
	// see, so the rule holds there or it does not hold.
	if got.Link != "https://psirt.example/" {
		t.Errorf("the composed address is %q, want the front door", got.Link)
	}
}

func TestAMessageAboutSomethingPublicCarriesWhatItIsAbout(t *testing.T) {
	// The other half of the no-detail rule, and as important: a public
	// vulnerability in a shipped component is public.
	// A channel that says nothing about anything is one people stop
	// reading, and then the embargo messages go unread with the rest.
	n := Notification{
		Kind: Assigned,
		Body: "CVE-2025-60876 in busybox-binsh, in openpsirt main container",
		Link: "/products/openpsirt/streams/main/variants/container/findings/CVE-2025-60876",
	}
	got := Compose(n, "https://psirt.example")

	for _, wanted := range []string{"CVE-2025-60876", "busybox-binsh", "openpsirt"} {
		if !strings.Contains(got.Text, wanted) {
			t.Errorf("the message does not say %q, which is what makes it worth opening:\n%s",
				wanted, got.Text)
		}
	}
	if !strings.Contains(got.Text, "https://psirt.example/products/openpsirt/") {
		t.Errorf("the message carries no way to reach it:\n%s", got.Text)
	}
	if got.Link != "https://psirt.example"+n.Link {
		t.Errorf("the composed address is %q, want the finding itself", got.Link)
	}
}

func TestAMessageWithNowhereToPointStillSaysWhatItCameToSay(t *testing.T) {
	// A deployment that has not been told the address people arrive on cannot
	// make a link, and half an address is worse than none: it looks like it
	// works and lands nowhere.
	n := Notification{Kind: Assigned, Body: "CVE-2025-1 in libfoo", Link: "/findings/1"}
	got := Compose(n, "")
	if strings.Contains(got.Text, "http") {
		t.Errorf("a deployment with no address invented one:\n%s", got.Text)
	}
	if !strings.Contains(got.Text, "CVE-2025-1") {
		t.Errorf("the message lost what it was about:\n%s", got.Text)
	}
}

func TestASubjectSaysWhatKindOfThingAndNeverWhichOne(t *testing.T) {
	// A subject is the part shown without anybody opening anything, so it is
	// the same words whether or not the thing behind it is disclosed.
	public := Compose(Notification{Kind: Assigned, Body: "CVE-2025-1 in libfoo"}, "")
	private := Compose(Notification{Kind: Assigned, Body: "SONIC-2026-1 in swss", Private: true}, "")
	if public.Subject != private.Subject {
		t.Errorf("the subject differs by what it is about: %q against %q",
			public.Subject, private.Subject)
	}
	if public.Subject == "" {
		t.Error("a message with no subject is one a reader cannot triage in a list")
	}
}

func TestADigestNamesWhatIsDisclosedAndCountsWhatIsNot(t *testing.T) {
	// A digest is a message, so it cannot name an undisclosed finding —
	// and dropping those rows would be the opposite failure: somebody
	// reads "nothing to report" while an embargoed item sits unowned.
	//
	// So they become numbers. Severity and lateness, because "three
	// undisclosed" does not say whether to open the tool now or after
	// coffee, and a channel that cannot answer that is one people stop
	// reading.
	d := Digest{
		Mine: []Item{{
			Issue: "CVE-2025-60876", Component: "busybox-binsh", Version: "1.37.0-r31",
			Severity: "medium", Product: "openpsirt", Build: "main container",
		}},
		Withheld: Withheld{
			Count: 3, BySeverity: map[string]int{"critical": 1, "high": 2},
			Exploited: 1, Unowned: 2,
		},
	}
	got := d.Message("https://psirt.example")

	// The public part is named, because that is what makes it worth opening.
	for _, wanted := range []string{"CVE-2025-60876", "busybox-binsh", "openpsirt"} {
		if !strings.Contains(got.Text, wanted) {
			t.Errorf("the digest does not name %q:\n%s", wanted, got.Text)
		}
	}
	// The undisclosed part is counted, and the numbers say how urgent.
	for _, wanted := range []string{"3 findings", "1 critical", "2 high", "1 known to be exploited", "2 that nobody owns"} {
		if !strings.Contains(got.Text, wanted) {
			t.Errorf("the digest does not say %q:\n%s", wanted, got.Text)
		}
	}
	// And the subject says nothing about any of it, because a preview shows a
	// subject without anybody opening anything.
	if strings.Contains(got.Subject, "CVE") || strings.Contains(got.Subject, "openpsirt") {
		t.Errorf("the subject names what it is about: %q", got.Subject)
	}
}

func TestADigestWithNothingToSayIsNotAMessage(t *testing.T) {
	// A daily "nothing" is how somebody learns to stop opening the daily
	// message, and then the ones that say something go unread with it.
	if !(Digest{}).Empty() {
		t.Error("an empty digest does not read as empty")
	}
	if (Digest{Withheld: Withheld{Count: 1}}).Empty() {
		t.Error("a digest with something withheld reads as empty, so nobody is told it exists")
	}
}

func TestEveryKindOfNotificationHasASubjectOfItsOwn(t *testing.T) {
	// The table is hand-maintained over a closed vocabulary with nothing
	// asserting that the two agree, and it was one row short. The kind it was
	// missing shipped under the generic fallback — and it is the one whose
	// whole purpose is a specific sentence, so a destination subscribed to it
	// alone received an alert indistinguishable from any other.
	for _, kind := range Kinds() {
		got := Compose(Notification{Kind: kind}, "https://psirt.example.test")
		if got.Subject == "" {
			t.Errorf("%s has no subject at all", kind)
		}
		if got.Subject == generalSubject {
			t.Errorf("%s has no subject of its own", kind)
		}
	}
}

func TestTheListOfKindsIsEveryKindDeclared(t *testing.T) {
	// The enumeration is hand-maintained too, so a kind added to the constants
	// and not to it would leave the check above passing while the new kind
	// shipped under the fallback — the same accident one step further back.
	//
	// Read from the source rather than from a second hand-written list, which
	// would be a third copy to keep in step.
	file, err := parser.ParseFile(token.NewFileSet(), "notify.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			named, ok := value.Type.(*ast.Ident)
			if !ok || named.Name != "Kind" {
				continue
			}
			for _, name := range value.Names {
				declared[name.Name] = true
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no kind constants were found in the source, so this checked nothing")
	}

	listed := map[Kind]bool{}
	for _, kind := range Kinds() {
		listed[kind] = true
	}
	if len(listed) != len(declared) {
		t.Errorf("Kinds() lists %d and the source declares %d", len(listed), len(declared))
	}
}
