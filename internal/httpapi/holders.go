package httpapi

import (
	"context"
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// HolderBody is somebody or something work can be handed to.
type HolderBody struct {
	Kind     string `json:"kind" enum:"person,team" doc:"Whether this is a person or a team. Work is held by a party, and both are one"`
	Identity string `json:"identity" doc:"What names it when handing work over"`
	Name     string `json:"name" doc:"What to show, which is the spelling somebody typed where there is one"`
}

// teamShare is how much of the picker teams may take.
//
// A few, because there are few of them and a team buried under twenty-five
// names is one nobody finds — and no more, because the bound covers the merged
// answer and a picker that is all teams and no people is not a picker.
const teamShare = 5

// registerHolders answers who may be given work here.
//
// **Assigning and mentioning are different questions**, and the interface was
// asking the mentions endpoint both. That endpoint answers who can already
// *read* a finding, which is right for offering a name inside text and wrong
// here twice over: a team cannot be mentioned in prose but is a perfectly good
// holder of work, and being able to read something is not the same as being
// somebody you may hand it to. The consequence was that no finding could be
// assigned to a team from the interface at all, though the API has taken one
// from the start.
//
// **It inherits what the mentions endpoint was built to avoid**. Per
// product, capped, an identity and a name and nothing else, narrowed on the
// server so a picker at a hundred people does not fetch them all. It is not a
// view over the people list, which is the administrator's directory: a lookup
// answering "does this person have an account here" to anybody who may triage
// is a staff directory for the price of one request.
//
// **Teams are named to anybody**, which is already true of the teams list: a
// team grants no role, no visibility and no capability, so its name discloses
// nothing that its existence does not. Membership stays an administrator's.
func registerHolders(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-holders", Method: http.MethodGet,
		Path:    "/v1/products/{product}/holders",
		Summary: "List who work here can be given to",
		Description: "People and teams that can hold work in this product, for a picker.\n\n" +
			"**People are those who can already read what they would be given**, at the " +
			"visibility asked for. Offering somebody who cannot open what they are handed " +
			"is how work arrives with a person who cannot act on it — and on an undisclosed " +
			"finding the offer itself would say a finding exists.\n\n" +
			"**Teams are listed whole.** A team holds work and grants nothing, so one " +
			"carries mixed clearance as a matter of course and what each member sees of " +
			"what is routed to it is what they could see anyway.\n\n" +
			"Narrow with `q`, which matches the identity and the displayed name without " +
			"regard to capitals. This is not the people list: that is the deployment's " +
			"directory and needs administration.",
		Tags: []string{"Triage"},
	}, perProduct, "Asking about undisclosed findings needs private-read or "+
		"private-triage.", readRights()...), func(ctx context.Context, input *struct {
		Product    string `path:"product"`
		Visibility string `query:"visibility" default:"public" enum:"public,private" doc:"The visibility of the work being handed over"`
		Term       string `query:"q" maxLength:"100" doc:"Narrow to names containing this, ignoring capitals"`
		Limit      int    `query:"limit" default:"25" minimum:"1" maximum:"100"`
	}) (*listOutput[HolderBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// Asking who may hold undisclosed work is itself a question about
		// undisclosed work, and is answered the way every other path answers
		// it: as though the product were not there.
		wanted := access.AsVisibility(input.Visibility)
		if !subject.Reads(wanted, product.ID) {
			return nil, noSuchProduct()
		}

		store := access.NewStore(in.DB.DB)
		people, err := store.WhoCanRead(ctx, subject, product.ID, wanted, input.Term, input.Limit)
		if err != nil {
			return nil, wentWrong(in.Logger, "who may hold this could not be read", err)
		}
		// Narrowed by the same term, and asked for one more than the share so
		// that a deployment past the share can be told from one at it.
		teams, err := store.Teams(ctx, input.Term, teamShare+1)
		if err != nil {
			return nil, wentWrong(in.Logger, "which teams there are could not be read", err)
		}
		moreTeams := len(teams) > teamShare
		if moreTeams {
			teams = teams[:teamShare]
		}

		out := &listOutput[HolderBody]{}
		out.Body.Items = make([]HolderBody, 0, len(people)+len(teams))
		// Teams first, and only a few of them. There are few beside the people,
		// and a picker that buries three teams under twenty-five names is one
		// where the team is never found — but one that spends the whole bound
		// on teams is worse: with the bound applied to the merged answer, a
		// deployment holding twenty-five teams opened this on twenty-five
		// teams and no people at all, which is a harder failure than the
		// unbounded list it replaced.
		named := make([]HolderBody, 0, len(teams))
		for _, team := range teams {
			shown := team.DisplayName
			if shown == "" {
				shown = team.Name
			}
			named = append(named, HolderBody{Kind: "team", Identity: team.Name, Name: shown})
		}
		sort.Slice(named, func(i, j int) bool { return named[i].Identity < named[j].Identity })
		out.Body.Items = append(out.Body.Items, named...)
		for _, person := range people {
			if len(out.Body.Items) >= input.Limit {
				break
			}
			out.Body.Items = append(out.Body.Items, HolderBody{
				Kind: "person", Identity: person.Identity, Name: person.Name,
			})
		}
		// How many there are to choose from, so a picker showing a page of
		// them can say so rather than passing the page off as the whole.
		// Counted rather than derived from the page for the reason every other
		// capped listing here states: a figure taken off a page answers a
		// different question from the one it looks like.
		total, err := store.CountWhoCanRead(ctx, subject, product.ID, wanted, input.Term)
		if err != nil {
			return nil, wentWrong(in.Logger, "who may hold this could not be counted", err)
		}
		teamsTotal := len(named)
		if moreTeams {
			if teamsTotal, err = store.CountTeams(ctx, input.Term); err != nil {
				return nil, wentWrong(in.Logger, "which teams there are could not be counted", err)
			}
		}
		out.Body.Total = total + teamsTotal
		return out, nil
	})
}
