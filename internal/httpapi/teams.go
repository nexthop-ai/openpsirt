package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// TeamBody is a team and who is on it.
type TeamBody struct {
	Name string `json:"name" doc:"What the team is called. Matched without regard to capitals"`
	// DisplayName is the spelling somebody typed, which is what is shown back.
	DisplayName string `json:"display_name,omitempty"`
	// Members are the people on it, by sign-in identity. Membership says where
	// work arrives, never what anybody may read.
	Members []string `json:"members"`
}

// TeamRecordBody declares a team, and optionally who is on it.
type TeamRecordBody struct {
	Name        string   `json:"name" minLength:"1" doc:"What to call the team"`
	DisplayName string   `json:"display_name,omitempty" doc:"How to spell it when it is shown. Defaults to the name"`
	Members     []string `json:"members,omitempty" doc:"Who is on it, by sign-in identity. Everybody named must already have been recorded"`
}

func registerTeams(api huma.API, a Administering) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-teams", Method: http.MethodGet, Path: "/v1/teams",
		Summary: "List teams",
		Description: "Lists the teams work can be routed to.\n\n" +
			"A team holds work and grants nothing: no role, no visibility, no capability. " +
			"One team therefore carries mixed clearance as a matter of course, and what each " +
			"member sees of the work routed to it is what they could see anyway.\n\n" +
			"**Names to anybody, membership to an administrator.** Routing work to a team " +
			"means naming one, so anybody who may hand work around has to be able to see the " +
			"names; who is on it is the same question as who is here, and that is answered " +
			"where the rest of the record is.",
		Tags: []string{"Administration"},
	}, anyPerson, "Membership is listed for an administrator; anybody else sees the names."),
		func(ctx context.Context, _ *struct{}) (*listOutput[TeamBody], error) {
			if _, err := reading(ctx); err != nil {
				return nil, err
			}
			if a.Access == nil {
				return nil, noDatabase(a.Logger)
			}
			store := a.Access()
			if store == nil {
				return nil, noDatabase(a.Logger)
			}
			teams, err := store.Teams(ctx, "", database.InBulk.Most)
			if err != nil {
				return nil, wentWrong(a.Logger, "cannot list teams", err)
			}
			// The whole-answer count, because the listing is capped: a
			// caller cannot tell a clipped page from every team there is
			// otherwise, and the ceiling is high rather than absent.
			total, err := store.CountTeams(ctx, "")
			if err != nil {
				return nil, wentWrong(a.Logger, "cannot count the teams", err)
			}
			// Membership is who is here, which is answered where the rest of
			// the record is: to an administrator.
			members := administrating(ctx) == nil

			out := &listOutput[TeamBody]{}
			out.Body.Total = total
			out.Body.Items = make([]TeamBody, 0, len(teams))
			for _, team := range teams {
				body := TeamBody{
					Name: team.Name, DisplayName: team.DisplayName, Members: []string{},
				}
				if members {
					if body, err = teamBody(ctx, store, team); err != nil {
						return nil, wentWrong(a.Logger, "cannot read who is on a team", err)
					}
				}
				out.Body.Items = append(out.Body.Items, body)
			}
			return out, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-team", Method: http.MethodPost, Path: "/v1/teams",
		Summary: "Create a team",
		Description: "Records a team so that work can be routed to it. Recording the same " +
			"name again returns the team and adds any members named, so a script that sets a " +
			"deployment up stays runnable.\n\n" +
			"Everybody named must already have been recorded: a team cannot bring somebody " +
			"into the deployment, because it grants nothing and an account that exists is " +
			"access somebody decided to give.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Body TeamRecordBody
	}) (*declaredOutput[TeamBody], error) {
		store, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}

		_, before := store.TeamByName(ctx, in.Body.Name)
		// Declaring a team and putting people on it is one act. Written as a
		// declaration and then a statement per member, a name nobody holds
		// left the team standing with whoever came before it on it, and the
		// caller a 404 saying nothing had happened.
		var team *access.Team
		if err := store.Within(ctx, func(ctx context.Context, store *access.Store, _ bun.IDB) error {
			var err error
			if team, err = store.DeclareTeam(ctx, in.Body.Name, in.Body.DisplayName); err != nil {
				return asked(a.Logger, err)
			}
			for _, identity := range in.Body.Members {
				person, err := store.ByIdentity(ctx, identity)
				if err != nil {
					return noSuchPerson()
				}
				if err := store.AddToTeam(ctx, team.ID, person.ID, by.ID); err != nil {
					return wentWrong(a.Logger, "cannot put somebody on a team", err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
		for _, identity := range in.Body.Members {
			// Recorded here as well as on the route that adds one later.
			// Somebody put on a team at the moment it is declared is on it the
			// same way, and a trail that has one and not the other is a trail
			// somebody has to know the history of to read.
			noteAdminChange(ctx, a, trail.Team, team.Name+" · "+identity,
				nil, trail.Said("a member", true))
		}

		body, err := teamBody(ctx, store, *team)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read who is on a team", err)
		}
		if before != nil {
			noteAdminChange(ctx, a, trail.Team, team.Name, nil, trail.Said("declared", true))
		}
		return answer(before != nil, body), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-team", Method: http.MethodDelete, Path: "/v1/teams/{team}",
		Summary: "Retire a team",
		Description: "Takes a team out of use. Nothing new is routed to it and its membership " +
			"goes, while work already routed to it still names it — the row stays for the " +
			"same reason an account is deactivated rather than deleted.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Team string `path:"team"`
	}) (*struct{}, error) {
		store, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		team, err := store.TeamByName(ctx, in.Team)
		if err != nil {
			return nil, noSuchTeamNamed(in.Team)
		}
		if err := store.RetireTeam(ctx, team.ID); err != nil {
			if errors.Is(err, access.ErrNoSuchTeam) {
				return nil, noSuchTeamNamed(in.Team)
			}
			return nil, wentWrong(a.Logger, "cannot retire that team", err)
		}
		noteAdminChange(ctx, a, trail.Team, team.Name, trail.Said("in use", true), nil)
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-to-team", Method: http.MethodPut,
		Path:    "/v1/teams/{team}/members/{identity}",
		Summary: "Put somebody on a team",
		Description: "Adds somebody to a team. Saying it twice asserts the same thing.\n\n" +
			"It grants them nothing. What they see of the team's work is what they could see " +
			"anyway, so a team with one member who may read undisclosed work and four who " +
			"may not is an ordinary arrangement rather than a misconfiguration.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Team     string `path:"team"`
		Identity string `path:"identity"`
	}) (*struct{}, error) {
		store, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		team, err := store.TeamByName(ctx, in.Team)
		if err != nil {
			return nil, noSuchTeamNamed(in.Team)
		}
		person, err := store.ByIdentity(ctx, in.Identity)
		if err != nil {
			return nil, noSuchPerson()
		}
		if err := store.AddToTeam(ctx, team.ID, person.ID, by.ID); err != nil {
			return nil, wentWrong(a.Logger, "cannot put somebody on a team", err)
		}
		noteAdminChange(ctx, a, trail.Team, team.Name+" · "+in.Identity,
			nil, trail.Said("a member", true))
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "remove-from-team", Method: http.MethodDelete,
		Path:    "/v1/teams/{team}/members/{identity}",
		Summary: "Take somebody off a team",
		Description: "Removes somebody from a team. Work they have already taken stays " +
			"theirs: membership says where work arrives, not who holds what has arrived.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Team     string `path:"team"`
		Identity string `path:"identity"`
	}) (*struct{}, error) {
		store, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		team, err := store.TeamByName(ctx, in.Team)
		if err != nil {
			return nil, noSuchTeamNamed(in.Team)
		}
		person, err := store.ByIdentity(ctx, in.Identity)
		if err != nil {
			return nil, noSuchPerson()
		}
		// Mapped before the trail row, as every other withdrawal is: a
		// removal that matched nothing is not a removal, and recording it as
		// one says somebody stopped receiving work they were never sent.
		switch err := store.RemoveFromTeam(ctx, team.ID, person.ID); {
		case errors.Is(err, access.ErrNothingMatched):
			return nil, huma.Error404NotFound("they are not on that team")
		case err != nil:
			return nil, wentWrong(a.Logger, "cannot take somebody off a team", err)
		}
		noteAdminChange(ctx, a, trail.Team, team.Name+" · "+in.Identity,
			trail.Said("a member", true), nil)
		return &struct{}{}, nil
	})
}

// teamBody reads a team and who is on it, by the identity they sign in under.
func teamBody(ctx context.Context, store *access.Store, team access.Team) (TeamBody, error) {
	body := TeamBody{Name: team.Name, DisplayName: team.DisplayName, Members: []string{}}
	members, err := store.MembersOf(ctx, team.ID)
	if err != nil {
		return TeamBody{}, err
	}
	// The identity, because the field is documented as the identity people
	// sign in under and the route that takes somebody off a team resolves it.
	named, err := store.Handles(ctx, members)
	if err != nil {
		return TeamBody{}, err
	}
	for _, person := range members {
		body.Members = append(body.Members, named[person])
	}
	return body, nil
}

func noSuchTeamNamed(name string) error {
	return huma.Error404NotFound("no team is known as " + name)
}
