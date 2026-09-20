package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// howManyJudgments is how many judgments the document carries.
//
// A page rather than everything: an issue at a widely vendored component can
// carry hundreds, and what this document is for is being read.
const howManyJudgments = 200

// registerIssueDocument renders everything known about one issue.
//
// The question a customer inquiry arrives as: the issue, the products of ours
// carrying it, the decision about each, and the argument behind each judgment
// — in one document, so that two people answering the same inquiry answer it
// the same way.
//
// An internal document. It carries the reasoning behind each judgment,
// which is this deployment's argument rather than its word to a customer — the
// documents that go out are the advisory and the VEX, and both are assembled
// elsewhere and deliberately say less. The lead line says so, because a
// document that does not say who it is for is one somebody forwards.
func registerIssueDocument(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-issue-document", Method: http.MethodGet,
		Path:    "/v1/issues/{vulnerability}/document",
		Summary: "Render everything known about one issue",
		Description: "What the issue is, every build of yours that carries it, what was " +
			"decided about each and the reasoning behind it, as markdown — the form a " +
			"customer inquiry is answered from.\n\n" +
			"It is an internal document and says so. The reasoning is this deployment's " +
			"own argument; what goes to a customer is the advisory or the VEX document, both " +
			"of which are assembled elsewhere and say less on purpose.\n\n" +
			"Narrowed by what you may see, like every other read: two people asking get " +
			"different documents rather than one of them getting an error.\n\n" +
			"Nothing of yours affected is an answer, and the document says that rather than " +
			"refusing — which is what the inquiry is usually asking.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		written, err := issueDocument(ctx, in, subject, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		return &huma.StreamResponse{Body: func(hc huma.Context) {
			hc.SetHeader("Content-Type", "text/markdown; charset=utf-8")
			hc.SetStatus(http.StatusOK)
			_, _ = hc.BodyWriter().Write([]byte(written))
		}}, nil
	})
}

// issueDocument assembles it, from the same readers the screens use.
func issueDocument(ctx context.Context, in Ingest, subject access.Subject,
	name string) (string, error) {

	var out strings.Builder
	issues := finding.NewVulnerabilities(in.DB.DB)
	id, err := issues.ByName(ctx, name)
	if err != nil {
		// An identifier nobody here has seen answers as one that sits only in
		// products this reader cannot see, for the reason the issue's own
		// route answers both the same way.
		//
		// A read that could not be made is neither. That is what the
		// sentinel is for — a name nobody has filed is a 404 and a database
		// that is down is a fault — and answering a customer inquiry "nothing
		// of yours is affected" because a query failed is the worst of the
		// three answers.
		if !errors.Is(err, finding.ErrNoSuchIssue) {
			return "", wentWrong(in.Logger, "what issue this is could not be read", err)
		}
		return unaffected(name), nil
	}
	rows, total, err := finding.NewStore(in.DB.DB).Everywhere(ctx, subject, id, howManyJudgments)
	if err != nil {
		return "", wentWrong(in.Logger, "where this issue sits could not be read", err)
	}
	if total == 0 {
		return unaffected(name), nil
	}
	known, err := issues.Describe(ctx, id)
	if err != nil {
		return "", wentWrong(in.Logger, "what this issue is could not be read", err)
	}

	fmt.Fprintf(&out, "# %s\n\n", known.Identifier)
	out.WriteString("Internal. The reasoning below is ours rather than our word to a " +
		"customer; what goes out is the advisory or the VEX document.\n")
	fmt.Fprintf(&out, "\nAssembled %s.\n", time.Now().UTC().Format(time.DateOnly))

	// The issue itself, from what the feeds said.
	out.WriteString("\n## The issue\n\n")
	if known.Description != "" {
		fmt.Fprintf(&out, "%s\n\n", known.Description)
	}
	var said []string
	if known.Severity != "" {
		said = append(said, known.Severity)
	}
	if known.Score > 0 {
		// The scheme with the number, where one is recorded. A document that
		// leaves this deployment is read beside documents from elsewhere, and
		// a bare number cannot be placed against one on the other scheme.
		if known.ScoreVersion != "" {
			said = append(said, fmt.Sprintf("%.1f on CVSS %s", known.Score, known.ScoreVersion))
		} else {
			said = append(said, fmt.Sprintf("%.1f", known.Score))
		}
	}
	if known.Exploited {
		said = append(said, "known exploited")
	}
	if len(said) > 0 {
		fmt.Fprintf(&out, "- Rated %s\n", strings.Join(said, ", "))
	}
	if len(known.Aliases) > 0 {
		fmt.Fprintf(&out, "- Also known as %s\n", strings.Join(known.Aliases, ", "))
	}
	// The places it is written up, each address through the rule an address
	// stored beside a claim goes through: this is a document somebody
	// forwards.
	//
	// Read on its own, because the issue itself and the places it is written
	// up are two questions and the screens ask one each.
	references, err := issues.PointsAt(ctx, id)
	if err != nil {
		return "", wentWrong(in.Logger, "where this is written up could not be read", err)
	}
	for _, at := range pointing(known, references) {
		fmt.Fprintf(&out, "- <%s>\n", at)
	}

	// Its places, which are what the inquiry actually asks for.
	fmt.Fprintf(&out, "\n## Its places\n\n%s\n\n", howManyCarry(total, len(rows)))
	for _, row := range rows {
		fmt.Fprintf(&out, "- %s %s (%s) — %s %s",
			row.Product, row.Stream, row.Variant, row.Component, row.Version)
		if row.Places > 1 {
			fmt.Fprintf(&out, ", at %d places", row.Places)
		}
		fmt.Fprintf(&out, " — %s", stateSaid(row.State))
		if row.DueAt != nil {
			fmt.Fprintf(&out, ", due %s", row.DueAt.UTC().Format(time.DateOnly))
		}
		if row.FixedIn != "" {
			fmt.Fprintf(&out, ", fixed upstream in %s", row.FixedIn)
		}
		out.WriteString("\n")
	}

	// And what was decided, with the argument each judgment rests on.
	judged, decided, err := triage.NewStore(in.DB.DB).Audit(ctx, subject,
		triage.Filter{Issue: known.Identifier}, time.Time{}, time.Time{},
		howManyJudgments, 0)
	if err != nil {
		return "", wentWrong(in.Logger, "what was decided could not be read", err)
	}
	out.WriteString("\n## The decisions\n\n")
	if len(judged) == 0 {
		out.WriteString("Nothing. Every place of it is open and undecided.\n")
		return out.String(), nil
	}
	// Said where it is a page of a longer record, the way the places above
	// say it. An issue at a widely vendored component carries hundreds of
	// judgments, and stopping at two hundred silently reads as the whole of
	// it.
	if len(judged) < decided {
		fmt.Fprintf(&out, "%d judgments stand. The %d most recent are below.\n\n",
			decided, len(judged))
	}
	// Newest first, which is how the record reads: what stands now is what
	// somebody is looking for, and the history is under it.
	sort.SliceStable(judged, func(i, j int) bool {
		return judged[i].ProposedAt.After(judged[j].ProposedAt)
	})
	for _, one := range judged {
		body := judgedBody(one)
		fmt.Fprintf(&out, "- %s in %s — %s", body.Outcome, body.Product, body.State)
		if body.Standing {
			out.WriteString(", standing")
		}
		fmt.Fprintf(&out, ", proposed by %s on %s", body.ProposedBy, body.ProposedAt)
		if len(body.Approvals) > 0 {
			agreed := make([]string, 0, len(body.Approvals))
			for _, approval := range body.Approvals {
				said := approval.By
				if approval.WithdrawnAt != "" {
					said += " (withdrawn)"
				}
				agreed = append(agreed, said)
			}
			fmt.Fprintf(&out, ", agreed by %s", strings.Join(agreed, ", "))
		}
		out.WriteString("\n")
		if body.Reasoning != "" {
			// Indented under the judgment it belongs to, and left exactly as
			// it was typed: it went through the text policy when it was
			// written, and rewriting it here would be a second policy.
			for _, line := range strings.Split(strings.TrimSpace(body.Reasoning), "\n") {
				fmt.Fprintf(&out, "  > %s\n", line)
			}
		}
	}
	return out.String(), nil
}

// unaffected is the whole document where nothing this reader may see carries
// it.
//
// A document rather than a refusal: an inquiry arrives asking whether we are
// affected, and yes must not be the only answer this can give.
func unaffected(name string) string {
	return fmt.Sprintf("# %s\n\nNothing you can see carries this issue.\n\n"+
		"Assembled %s.\n", name, time.Now().UTC().Format(time.DateOnly))
}

// howManyCarry is the line above the list: how many builds carry it, and
// whether the list below is all of them.
func howManyCarry(total, shown int) string {
	what := "builds carry it"
	if total == 1 {
		what = "build carries it"
	}
	if shown < total {
		return fmt.Sprintf("%d %s. The %d worst are listed.", total, what, shown)
	}
	return fmt.Sprintf("%d %s.", total, what)
}

// stateSaid is how far a build has decided it, in words rather than in the
// vocabulary the database stores.
func stateSaid(state string) string {
	switch state {
	case "agreed":
		return "agreed"
	case "waiting":
		return "waiting for a second person"
	case "lapsed":
		return "the judgment here no longer stands"
	case "undecided":
		return "nobody has said"
	}
	return "part decided"
}

// pointing is every address held for an issue that a reader may safely be
// handed, in a stable order.
func pointing(known finding.Named, references []finding.Reference) []string {
	seen := map[string]bool{}
	var out []string
	for _, at := range append([]string{known.Advisory}, urlsOf(references)...) {
		at = strings.TrimSpace(at)
		if at == "" || seen[at] || markdown.Autolinkable(at) != nil {
			continue
		}
		seen[at] = true
		out = append(out, at)
	}
	sort.Strings(out)
	return out
}

// urlsOf is the addresses of a set of references.
func urlsOf(references []finding.Reference) []string {
	out := make([]string, 0, len(references))
	for _, one := range references {
		out = append(out, one.URL)
	}
	return out
}
