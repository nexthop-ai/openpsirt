package httpapi

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The lists that could be read on a screen and not taken away.
//
// **An export is not a convenience here.** The record of judgments is what an
// auditor is given, the review queue is what a manager reports a backlog from,
// and the by-component view is what a release meeting argues over — and all
// three were screens somebody had to copy out of by hand.
//
// **The subject travels through the stream**, as it does for the findings
// export: the same query the screen reads, paged and written out as it goes,
// with no point at which a whole unnarrowed list exists to be filtered
// afterwards. That is the failure an export is the easiest place to make.
//
// **The same filters as the screen, from the same struct.** An export taking a
// smaller set would be a file that quietly answers a different question from
// the one on screen, which is worse than no export: nothing about the file
// says it.

func registerMoreExports(api huma.API, in Ingest) {
	registerAuditExport(api, in)
	registerChangeExport(api, in)
	registerQueueExport(api, in)
	registerComponentExport(api, in)
	registerDueExport(api, in)
	registerComparisonExport(api, in)
}

// registerDueExport writes out what is running out of time.
//
// The deadline report is the one somebody takes to a meeting about dates, and
// it was the one list that could not leave the screen — which meant the answer
// to "what is late" was retyped, and a retyped list is one that is wrong by the
// meeting after next.
func registerDueExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-running-out", Method: http.MethodGet,
		Path:    "/v1/running-out.{format}",
		Summary: "Export what is running out of time",
		Description: "Open findings whose deadline falls within `days` and which nobody has " +
			"decided about, as a file: every row, not the page the screen shows.\n\n" +
			"The same list the screen reads, under the same rule — a deadline that has been " +
			"answered is not on it, because a dismissal takes a finding off the clock and a " +
			"deferral replaces the deadline with its own date. What is left is time passing " +
			"with nothing said.\n\n" +
			"`days_left` is negative once something is overdue.",
		Tags: []string{"Findings"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		ScopeQuery
		Days int `query:"days" default:"14" minimum:"0" maximum:"365" doc:"How far ahead to look"`
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		store := finding.NewStore(in.DB.DB)
		rights := access.NewStore(in.DB.DB)
		now := time.Now().UTC()
		out := Exporting{
			What:  "what is running out of time",
			About: []Stated{{"looking ahead days", strconv.Itoa(input.Days)}},
			Header: []string{
				"issue", "severity", "exploited", "component", "version",
				"product", "stream", "variant", "places", "held by", "due", "days left",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				late, _, err := store.RunningOutPage(ctx, subject, scope,
					time.Duration(input.Days)*24*time.Hour, limit, offset)
				if err != nil {
					return nil, err
				}
				owners := make([]int64, 0, len(late))
				for _, row := range late {
					if row.AssignedTo != nil {
						owners = append(owners, *row.AssignedTo)
					}
				}
				// A person or a team: the column holds a
				// party, and a file naming only people would
				// report a team's work as nobody's .
				who, err := rights.WhoHolds(ctx, owners)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(late))
				for _, row := range late {
					held := ""
					if row.AssignedTo != nil {
						held = who[*row.AssignedTo].Name
					}
					rows = append(rows, []string{
						row.Vulnerability, row.Severity,
						strconv.FormatBool(row.Exploited),
						row.Component, row.Version,
						row.Product, row.Stream, row.Variant,
						strconv.Itoa(row.Places), held,
						row.Due.Format(time.DateOnly),
						// Rounded down rather than toward zero, the way the
						// screen rounds it: truncation reports something twelve
						// hours overdue as having zero days left, which reads
						// as due today.
						strconv.Itoa(int(math.Floor(row.Due.Sub(now).Hours() / 24))),
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "running-out", out)
		}}, nil
	})
}

// registerComparisonExport writes out what changed between two builds.
//
// The comparison is what a release note is written from, and its destination is
// usually a document somebody else edits — so the one thing it needed was to
// leave the screen, and it could not.
//
// One file rather than three, with a column saying which of the three each row
// belongs to: what is fixed, newly present and still present is one comparison,
// and three files are three things to keep together by hand.
func registerComparisonExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-comparison", Method: http.MethodGet,
		Path:    "/v1/products/{product}/comparison.{format}",
		Summary: "Export a comparison of two builds",
		Description: "What was fixed, what is newly present and what is still there between " +
			"two builds, as a file.\n\n" +
			"One file with a `change` column rather than three files: it is one comparison, " +
			"and three of anything that has to be kept together is three chances to send " +
			"somebody two of them.\n\n" +
			"Each fixed row says why it went. `superseded` is the one to read carefully — the " +
			"version moved and the issue came with it, so it was not fixed at all. A " +
			"still-present row carrying `arrived from` is that same failure from the other " +
			"side.\n\n" +
			"**Public findings only unless you ask otherwise**, because the destination is " +
			"usually a public document.",
		Tags: []string{"Findings"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product        string `path:"product"`
		Format         string `path:"format" enum:"csv,json"`
		From           string `query:"from" required:"true" doc:"The earlier build's stream — a branch or a tag"`
		FromVariant    string `query:"from_variant" required:"true" doc:"The earlier build's variant"`
		To             string `query:"to" required:"true" doc:"The later build's stream"`
		ToVariant      string `query:"to_variant" required:"true" doc:"The later build's variant"`
		IncludePrivate bool   `query:"include_undisclosed" doc:"Include findings nobody has disclosed"`
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		locate := func(stream, variant string) (int64, error) {
			return targetIDOf(ctx, in, subject, input.Product, stream, variant)
		}
		from, err := locate(input.From, input.FromVariant)
		if err != nil {
			return nil, err
		}
		to, err := locate(input.To, input.ToVariant)
		if err != nil {
			return nil, err
		}
		// Read whole rather than paged, unlike every other export here: a
		// comparison is one answer computed from two builds at once and there
		// is no page of it to ask for. Bounded by what two builds hold, which
		// is what the screen already reads.
		comparison, err := finding.NewStore(in.DB.DB).Compare(ctx, subject, from, to,
			input.IncludePrivate)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := Exporting{
			What: "comparison of two builds",
			// Which two builds, because a file headed "comparison" and
			// naming neither of them is a document nobody can check against
			// anything, and whether the undisclosed ones are in it: a file
			// that leaves them out reads as complete about what remains.
			About: []Stated{
				{"earlier build", input.From + " (" + input.FromVariant + ")"},
				{"later build", input.To + " (" + input.ToVariant + ")"},
				{"includes undisclosed", strconv.FormatBool(input.IncludePrivate)},
			},
			Header: []string{
				"change", "issue", "component", "severity", "because",
				"from version", "moved to", "arrived from", "closed by run",
				"state", "outcome", "justification", "due",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				if offset > 0 {
					return nil, nil
				}
				rows := make([][]string, 0, len(comparison.Fixed)+len(comparison.Closed)+
					len(comparison.Newly)+len(comparison.Still))
				for _, group := range []struct {
					what string
					of   []finding.Changed
					// stands says the rows carry what the build decided about
					// them, which is true of what is still there and of
					// nothing else: what was fixed needs no justification and
					// what is newly present has not been looked at yet.
					stands bool
				}{
					{what: "fixed", of: comparison.Fixed},
					// Apart from the fixes, by the same split the screen and
					// the release note read: a superseded bump and a closure
					// nothing explains are not work anybody did.
					{what: "closed, not fixed", of: comparison.Closed},
					{what: "newly present", of: comparison.Newly},
					{what: "still present", of: comparison.Still, stands: true},
				} {
					// Read through the same function the screen reads, so the
					// file cannot come to answer less than the screen it was
					// taken from — which is what it did: an approved
					// not-applicable and a row nobody had looked at were the
					// same nine columns.
					for _, body := range changed(group.of, true, group.stands) {
						closedRun := ""
						if body.ClosedRun != 0 {
							closedRun = strconv.FormatInt(body.ClosedRun, 10)
						}
						rows = append(rows, []string{
							group.what, body.Vulnerability, body.Component, body.Severity,
							body.Because, body.FromVersion, body.MovedTo, body.ArrivedFrom,
							closedRun, body.State, string(body.Outcome),
							string(body.Justification), body.Due,
						})
					}
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "comparison-"+downloadName(input.Product), out)
		}}, nil
	})
}

// asDay is a bound on a period as a file states it, and nothing where the
// period has no bound on that side.
func asDay(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.DateOnly)
}

// registerAuditExport writes out the record of judgments.
func registerAuditExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-audit", Method: http.MethodGet, Path: "/v1/audit.{format}",
		Summary: "Export the record of judgments",
		Description: "The audit list as a file: every judgment the same filters would show, " +
			"not one page of them.\n\n" +
			"**One row per judgment**, with who proposed it, who has a standing agreement on " +
			"it, and whether a second person does. Approvals are joined with `;` in the CSV " +
			"because a spreadsheet has one cell per column and an auditor reads them as a " +
			"list; the JSON keeps them as one field of the same shape.\n\n" +
			"**`agreements` is the whole of the record**, with dates: who agreed, when, " +
			"whether the agreement was carried from an earlier claim, and when it was taken " +
			"back. `approved by` stays who agrees *now*, because those are different " +
			"questions and a column mixing them is the one answer an auditor must not be " +
			"given.\n\n" +
			"**Read with your own visibility, as it streams.** Nothing about a report is " +
			"exempt from the rules the screens follow — a file showing more than the screen " +
			"that summarizes it would be a way around them.\n\n" +
			"Takes every filter the audit list takes, including the period.",
		Tags: []string{"Reports"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Auditing
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		filter, since, until, err := input.narrow(ctx, in, subject)
		if err != nil {
			return nil, err
		}
		out := Exporting{
			What:  "the record of judgments",
			About: []Stated{{"from", asDay(since)}, {"to", asDay(until)}},
			Header: []string{
				"id", "proposed", "product", "issue", "component", "version", "consumer",
				"outcome", "justification", "deferred until", "fixed version",
				"state", "standing", "proposed by", "approved by", "two people", "ended",
				"agreements", "reasoning",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				judged, _, err := store.Audit(ctx, subject, filter, since, until, limit, offset)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(judged))
				for _, row := range judged {
					body := judgedBody(row)
					// Only the agreements that still stand. One taken back is
					// in the record and is not somebody who agrees now, and a
					// column that mixed the two would be the exact answer an
					// auditor must not be given.
					agreed := make([]string, 0, len(body.Approvals))
					for _, one := range body.Approvals {
						if one.WithdrawnAt == "" {
							agreed = append(agreed, one.By)
						}
					}
					// And the whole of the record beside it, dates and all.
					// The column above is who agrees now, which is what an
					// auditor reads first; what somebody agreed to and then
					// stopped agreeing to is what an audit is looking for,
					// and the file carried neither it nor any date at all.
					every := make([]string, 0, len(body.Approvals))
					for _, one := range body.Approvals {
						said := one.By + " " + one.At
						if one.Carried {
							said += " carried"
						}
						if one.WithdrawnAt != "" {
							said += " withdrawn " + one.WithdrawnAt
						}
						every = append(every, said)
					}
					rows = append(rows, []string{
						strconv.FormatInt(body.ID, 10), body.ProposedAt, body.Product,
						body.Issue, body.Component, body.Version, body.Consumer,
						string(body.Outcome), string(body.Justification), body.DeferredUntil,
						body.FixedVersion, body.State,
						strconv.FormatBool(body.Standing),
						body.ProposedBy, strings.Join(agreed, "; "),
						strconv.FormatBool(body.TwoPeople), body.EndedAt,
						strings.Join(every, "; "), body.Reasoning,
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "audit", out)
		}}, nil
	})
}

// registerQueueExport writes out what is waiting for a second person.
func registerQueueExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-review-queue", Method: http.MethodGet,
		Path:    "/v1/review-queue.{format}",
		Summary: "Export the review queue",
		Description: "What is waiting for a second person, as a file: every claim, not one " +
			"page of them.\n\n" +
			"**One row per claim**, the way the screen counts them — one proposer's action, " +
			"however many decisions it wrote — with how much it covers and how old it is. " +
			"A backlog is reported in claims because that is the unit somebody works " +
			"through.\n\n" +
			"Limited to what you may approve every row of, as the screen is, and your own " +
			"claims are not in it. `mine=true` writes out what you proposed and nobody has " +
			"agreed to, which is a different question, and `product` narrows it the way the " +
			"screen does.",
		Tags: []string{"Triage"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format  string `path:"format" enum:"csv,json"`
		Mine    bool   `query:"mine" doc:"Write out what you proposed and nobody has agreed to, instead of what is waiting on you"`
		Product string `query:"product" doc:"Limit to claims made in one product, by name. Empty means every product you can see; a name you cannot see is refused rather than answered empty"`
	}) (*huma.StreamResponse, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// Narrowed the same way the list is, so a file taken from a narrowed
		// screen is the narrowed backlog rather than the whole one.
		within, err := narrowedTo(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		out := Exporting{
			What: "the review queue",
			Header: []string{
				"claim", "proposed", "proposed by", "age days", "outcome", "issue",
				"product", "component", "decisions", "issues", "places", "builds",
				"previously approved", "deferred days", "reasoning",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				waiting, _, err := store.Queue(ctx, subject, input.Mine, within, limit, offset)
				if err != nil {
					return nil, err
				}
				if len(waiting) == 0 {
					return nil, nil
				}
				// The names, in one pass over the page rather than per row —
				// the same call the screen makes, so the file and the screen
				// say the same thing about the same claim.
				decisions := make([]triage.Decision, 0, len(waiting))
				for _, row := range waiting {
					decisions = append(decisions, row.Decision)
				}
				named, err := describeDecisions(ctx, in, store, decisions, nil)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(waiting))
				for i, row := range waiting {
					where := named[i].Finding
					product, component, version := "", "", ""
					if where != nil {
						product, component = where.Product, where.Component
						version = where.Version
					}
					rows = append(rows, []string{
						strconv.FormatInt(row.Claim.ID, 10),
						stamp(row.Decision.ProposedAt),
						named[i].ProposedBy,
						strconv.Itoa(int(store.Age(&row.Decision).Hours() / 24)),
						string(row.Claim.Outcome),
						named[i].Place.Vulnerability,
						product, component + " " + version,
						strconv.Itoa(row.Decisions), strconv.Itoa(row.Issues),
						strconv.Itoa(row.Places),
						strings.Join(row.Builds, "; "),
						strconv.FormatBool(row.PreviouslyApproved),
						strconv.Itoa(int(row.DeferredSoFar.Hours() / 24)),
						row.Reasoning,
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "review-queue", out)
		}}, nil
	})
}

// registerComponentExport writes out what is open, gathered by component.
func registerComponentExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-finding-components", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings/components.{format}",
		Summary: "Export findings by component",
		Description: "One row per component and version, with how many distinct issues are " +
			"open against it and how many places those sit at — every row, not one page.\n\n" +
			"This is the shape a release meeting argues over: where the weight is rather " +
			"than what is wrong. On a switch operating-system image the kernel carried 4,943 " +
			"of 6,822 findings rows and the next largest contributor carried 58, which is a " +
			"one-line answer here and invisible in a list of issues.\n\n" +
			"Takes the same filters as the by-component list, and the line this deployment " +
			"triages at is stated in the file.",
		Tags: []string{"Findings"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Format  string `path:"format" enum:"csv,json"`
		Stream  string `query:"stream"`
		Variant string `query:"variant"`
		AtOneBuild
		Narrowing
	}) (*huma.StreamResponse, error) {
		at, err := narrowing(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "the triage line could not be read")
		if err != nil {
			return nil, err
		}
		subject, scope, floor, narrowed, store := at.Subject, at.Scope, at.Floor, at.Filter, at.Store
		line := "everything"
		if floor.Hides() {
			line = floor.Word
		}
		out := Exporting{
			What:   "findings by component",
			About:  []Stated{{"triaged at or above", line}},
			Header: []string{"component", "version", "upstream", "ecosystem", "issues", "places", "exploited"},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				groups, _, err := store.ComponentGroups(ctx, subject, scope, limit, offset, narrowed)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(groups))
				for _, g := range groups {
					rows = append(rows, []string{
						g.Component, g.Version, g.Upstream, g.Ecosystem,
						strconv.Itoa(g.Issues), strconv.Itoa(g.Places),
						strconv.FormatBool(g.Exploited),
					})
				}
				return rows, nil
			},
		}
		name := "components-" + strings.ToLower(input.Product)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, name, out)
		}}, nil
	})
}

// registerChangeExport writes out what has been changed administratively.
//
// The change log was capped at fifty rows, undated and unexportable, and
// reached by scrolling past a hundred audit cards. What an audit asks of it —
// "show me every grant made in the year the certificate covers" — could be
// read a page at a time on a screen and could not leave it.
func registerChangeExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-administrative-changes", Method: http.MethodGet,
		Path:    "/v1/administration/changes.{format}",
		Summary: "Export administrative changes",
		Description: "Every administrative change the same filters would show, as a file, " +
			"rather than one page of them.\n\n" +
			"**One row per change**, with who made it, what it was about, and what it held " +
			"before and after. An absent value is not an empty one: `unset` says nobody had " +
			"set it, and `cleared` that the change removed it.\n\n" +
			"Takes the kind and the period the list takes. Asked for no period it writes " +
			"everything this deployment holds.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		Kind   string `query:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias" doc:"Keep only changes of one kind"`
		Period
	}) (*huma.StreamResponse, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		since, until, err := input.window(0, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		store := trail.NewStore(in.DB.DB)
		rights := access.NewStore(in.DB.DB)
		out := Exporting{
			What: "what has been changed administratively",
			About: []Stated{
				{"from", asDay(since)}, {"to", asDay(until)}, {"kind", input.Kind},
			},
			Header: []string{"at", "by", "kind", "about", "was", "became", "unset", "cleared"},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				changes, _, err := store.Changes(ctx, subject, trail.Kind(input.Kind),
					trail.Over{Since: since, Until: until}, limit, offset)
				if err != nil {
					return nil, err
				}
				// Who, by the identity they sign in under, read a page at a
				// time like every other name this file carries.
				who := make([]int64, 0, len(changes))
				for _, change := range changes {
					who = append(who, change.By)
				}
				names, err := rights.Names(ctx, who)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(changes))
				for _, change := range changes {
					rows = append(rows, []string{
						change.At.UTC().Format(time.RFC3339), names[change.By],
						string(change.Kind), change.Name,
						orBlank(change.Was), orBlank(change.Became),
						strconv.FormatBool(change.Was == nil),
						strconv.FormatBool(change.Became == nil),
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "administrative-changes", out)
		}}, nil
	})
}
