package notify

import (
	"fmt"
	"strings"
)

// Message is one thing to carry outside the application.
//
// Composed here rather than by a channel, so that what may be said is decided
// once for every channel there will ever be. A chat adapter that shaped its
// own text would be a second place to get the embargo rule right, and the
// second place is the one that is wrong.
type Message struct {
	Subject string
	// Text is markdown, which is what a mail carries as its text part. A
	// chat adapter translates rather than forwarding it.
	Text string
	// Link is the address a channel may carry. For something undisclosed it
	// is the way in and never the thing itself, which is why it is composed
	// here with the text rather than rebuilt by whatever is carrying it: an
	// address built a second time is built without the rule.
	Link string
}

// what each kind is called where somebody reads it as a subject line.
//
// Deliberately plain and deliberately uninformative about which finding: a
// subject is shown by a preview without anybody opening anything, so it says
// what kind of thing this is and never what it is about.
//
// Kept against Kinds by a test, because this is a hand-maintained table over a
// closed vocabulary and it was one row short.
var called = map[Kind]string{
	Assigned:      "Work assigned to you",
	SentBack:      "A claim of yours was sent back",
	BuildQuiet:    "A build has stopped being scanned",
	HoldingAbsent: "Somebody away is holding work",
	// The one kind whose purpose is a specific sentence — "this release has a
	// critical, we need to cut a new one" — and the one this table was
	// missing, so it shipped as the fallback below.
	CriticalOnRelease: "A release carries an unaddressed critical",
	Mentioned:         "You were named in a note",
	DisclosureDue:     "An embargo has reached its date",
	DisclosureNear:    "An embargo is running out",
	StatementRevised:  "A VEX publisher changed what a decision cited",
	ClaimWaiting:      "A claim is waiting for a second person",
	SentBackWaiting:   "A claim of yours is waiting on you",
	DeferralEnding:    "A deferral is running out",
	QueueUntaken:      "Work is sitting in a team's queue",
	ApprovalUndone:    "An agreement to a claim of yours was taken back",
	ClaimLapsed:       "A decision of yours stopped applying",
	BroughtIn:         "You have been brought into a case",
	Unanswered:        "A vulnerability report has not been answered",
	InventoryMoved:    "A build's contents changed sharply",
	ObligationOpen:    "A window after an attack is running",
	ObligationNear:    "A window after an attack is about to end",
	ObligationPassed:  "A window after an attack has passed",

	VulnerabilityDataStale: "The vulnerability data has stopped moving",
	RiskUnagreed:           "Something is hidden with nobody agreeing",
	PairsConcentrated:      "One pair is agreeing to most of a product's work",
	SupplierSilent:         "A supplier has stopped answering",
}

// generalSubject is what a notification of no known kind is called.
const generalSubject = "Something needs your attention"

// Compose turns a notification into what a channel carries.
//
// The whole of the no-detail rule lives here. A
// notification about a finding nobody has announced carries the fact that
// there is something and a link, and nothing else — not the issue, not the
// component, not the build, and not in the subject, because a preview shows
// that without anybody opening anything.
//
// A disclosed finding carries its detail, which is what makes the message
// worth opening. A public vulnerability in a shipped component is public, and
// a channel that says nothing about anything is one people stop reading —
// after which the embargo messages go unread with the rest.
//
// The link is absolute, because a message is read somewhere this deployment is
// not: a path alone resolves against whatever mail client the reader has open.
func Compose(n Notification, baseURL string) Message {
	subject := called[n.Kind]
	if subject == "" {
		// Every kind has a line of its own, which a test holds, so this is a
		// belt for a kind that does not exist rather than a shape anything
		// ships under.
		subject = generalSubject
	}
	where := link(baseURL, n.Link)

	if n.Private {
		// One sentence, and it names nothing.
		//
		// Including the address. The decision says a link, and a link to the
		// finding defeats the rule it is part of: a path carrying the
		// identifier and the component announces both to every server the
		// message crosses, whatever the body was careful about. So what is
		// sent is the way in, and the notification area behind it — which is
		// reached with a credential and a visibility check — says which thing
		// and where.
		text := "Something that has not been disclosed needs your attention.\n\n" +
			"This message deliberately says no more than that, including in its " +
			"address: it travels outside the application, where the check on who " +
			"may read it does not reach. Your notifications say which thing.\n"
		front := link(baseURL, "/")
		if front != "" {
			text += "\n" + front + "\n"
		}
		return Message{Subject: subject, Text: text, Link: front}
	}

	text := strings.TrimSpace(n.Body)
	if text != "" {
		text += "\n"
	}
	if where != "" {
		text += "\n" + where + "\n"
	}
	return Message{Subject: subject, Text: text, Link: where}
}

// link makes the address a reader can follow from wherever they are.
//
// A deployment that has not been told the address people arrive on cannot make
// one, and half an address is worse than none: it is a link that looks like it
// works and lands nowhere. So it is left out, and the message still says the
// thing it was sent to say.
func link(baseURL, path string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	path = strings.TrimSpace(path)
	if baseURL == "" || path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s%s", baseURL, path)
}
