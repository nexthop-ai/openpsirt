// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// CanBody is one product somebody can reach, and what they may do in it.
//
// Named for the question it answers rather than for "reach", which already
// means something else here — how far a single judgment travels.
//
// The acts they may perform, not the roles they hold. A screen needs to know
// whether to offer an action, and answering that from a role list means every
// client re-implementing the mapping from roles to capabilities — which is the
// server's rule, and the copy that drifts is the one that offers a button
// leading to a refusal.
type CanBody struct {
	Product           string `json:"product"`
	Name              string `json:"name" doc:"The label shown for it"`
	MaySee            bool   `json:"may_see" doc:"Read findings here at either visibility"`
	ReadsPublic       bool   `json:"reads_public" doc:"Read findings that have been disclosed"`
	ReadsPrivate      bool   `json:"reads_private" doc:"Read findings nobody has disclosed yet"`
	MayTriage         bool   `json:"may_triage" doc:"Argue about a finding here at either visibility"`
	TriagesPublic     bool   `json:"triages_public" doc:"Argue about a finding that has been disclosed"`
	MayAssign         bool   `json:"may_assign" doc:"Give work to somebody else, or take what they hold — triage as well as the assigner role. Taking work nobody owns, and handing back your own, need only may_triage"`
	MayHide           bool   `json:"may_hide" doc:"Argue about a finding nobody has disclosed"`
	MayAgree          bool   `json:"may_agree" doc:"Agree to somebody else's claim, or send it back, at either visibility. The approver capability or a triage role on the product — a triager may answer somebody else's claim, which is the ordinary shape of a small team; that the two are different people is checked separately and has no override"`
	AgreesPublic      bool   `json:"agrees_public" doc:"Agree to somebody else's claim about disclosed findings, or send it back: reading them, with the approver capability or public-triage"`
	AgreesPrivate     bool   `json:"agrees_private" doc:"Agree to somebody else's claim about findings nobody has disclosed, or send it back: reading them, with the approver capability or private-triage"`
	MayApproveRulings bool   `json:"may_approve_rulings" doc:"Agree to somebody else's ruling on vulnerability reports: reading undisclosed work, with the approver capability or triage of undisclosed work"`
}

// WhoBody is the caller, as the caller.
type WhoBody struct {
	Identity string    `json:"identity" doc:"The identity this deployment holds for them"`
	Name     string    `json:"name" doc:"The display name, where one is recorded"`
	Admin    bool      `json:"admin" doc:"Administers this deployment"`
	Audits   bool      `json:"audits,omitempty" doc:"May read this deployment's own records — the settings, who holds what, and the administrative change log — and write none of them"`
	Kind     string    `json:"kind" enum:"person,key" doc:"A person who signed in, or a credential"`
	Reach    []CanBody `json:"reach" doc:"The products they can reach, and what they may do in each"`
	// Digest is the daily summary they asked for. Answered here because a
	// screen offering the switches has to know their state, and because a
	// person is the only one who decides them.
	Digest           bool `json:"digest,omitempty" doc:"They asked for a daily digest"`
	DigestUnassigned bool `json:"digest_unassigned,omitempty" doc:"Their digest lists findings nobody owns as well as their own outstanding work"`
	// Reachable says there is somewhere to send it. Without an address a
	// digest is a switch that changes nothing, and a screen should say so
	// rather than offer it.
	Reachable bool `json:"reachable,omitempty" doc:"An address is recorded for them, so anything can be sent at all"`
	// DeferralDays is the deployment's threshold, which a screen has to know
	// before somebody writes a date rather than after they submit one: a
	// deferral under it takes effect at once and one over it waits for a
	// second person, and that changes what somebody is about to do. It is a
	// policy rather than a secret — the same rule everybody here is subject
	// to — so it is answered to anybody who may ask about themselves.
	DeferralDays int `json:"deferral_days,omitempty" doc:"The deferral a second person has to agree past, in days. A screen taking a date needs it before the date is written, not after it is submitted"`
	// BulkCap is how many rows one action may write. A screen offering a
	// selection has to know it before the selection is acted on: a loop of
	// single writes bounded by nothing turns one click into as many round
	// trips as the filter matched, which is a page nobody can use and
	// nothing can cancel.
	BulkCap int `json:"bulk_cap,omitempty" doc:"The number of rows one action may write here. A screen acting on a selection bounds it by this, and says so, rather than discovering the limit one refusal at a time"`
}

func registerWhoAmI(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-current-subject", Method: http.MethodGet, Path: "/v1/session/me",
		Summary: "Describe the current subject",
		Description: "Returns the caller, the products they can reach, and what they may do in " +
			"each one.\n\n" +
			"It answers what a screen has to know before it draws: whether to offer an action " +
			"at all. Without it a client either hides nothing and lets people find the refusal, " +
			"or re-implements the mapping from roles to capabilities and drifts from the one " +
			"the server enforces.\n\n" +
			"Capabilities, not roles, for that reason. Which roles produce which capability is " +
			"the server's rule and stays there.",
		Tags: []string{"Access"},
	}, ownSubject, ""), func(ctx context.Context, _ *struct{}) (*struct{ Body WhoBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}

		body := WhoBody{
			Identity: subject.Identity, Admin: subject.Admin, Audits: subject.Audits,
			Kind: string(subject.Kind), Reach: []CanBody{},
		}
		if threshold, err := deferralThreshold(ctx, in); err == nil {
			body.DeferralDays = int(threshold.Hours() / 24)
		}
		if in.DB != nil {
			if cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
				triage.DefaultTogetherCap); err == nil {
				body.BulkCap = cap
			}
		}
		// The digest they asked for, where they are a person and this process
		// has somewhere to read it from. A credential asks for nothing and is
		// sent nothing.
		if in.DB != nil && subject.Kind == access.Person {
			if me, err := access.NewStore(in.DB.DB).ByIdentity(ctx, subject.Identity); err == nil {
				body.Digest = me.Digest
				body.DigestUnassigned = me.DigestUnassigned
				body.Reachable = strings.TrimSpace(me.Email) != ""
			}
		}

		if in.DB == nil {
			return &struct{ Body WhoBody }{Body: body}, nil
		}

		// The display name, where one is recorded. Falls back to the identity
		// rather than to nothing, so a header never renders blank.
		if subject.Kind == access.Person {
			named, err := access.NewStore(in.DB.DB).Names(ctx, []int64{subject.ID})
			if err != nil {
				return nil, wentWrong(in.Logger, "who you are could not be read", err)
			}
			body.Name = named[subject.ID]
		}
		if body.Name == "" {
			body.Name = subject.Identity
		}

		// Named, not numbered. Every other endpoint takes a product by name,
		// so returning identifiers here would make this the one answer a
		// client has to translate before it can use it.
		products, err := catalog.NewStore(in.DB.DB).Products(ctx, subject)
		if err != nil {
			return nil, wentWrong(in.Logger, "what you can reach could not be read", err)
		}
		for _, product := range products {
			// Assigning is triage plus assigner, not assigner alone: the
			// endpoint refuses somebody who holds the second and not the
			// first, so an interface drawing the control from this would
			// offer an action that always fails.
			triages := subject.TriagesIn(product.ID)
			// Asked at one visibility, as approving a claim is: reading it,
			// and the capability or triage there.
			agrees := func(v access.Visibility) bool {
				return subject.Reads(v, product.ID) &&
					(subject.Holds(access.Approver, product.ID) || subject.Triages(v, product.ID))
			}
			body.Reach = append(body.Reach, CanBody{
				Product: product.Name, Name: product.DisplayName,
				MaySee:        subject.ReadsIn(product.ID),
				ReadsPublic:   subject.Reads(access.Public, product.ID),
				ReadsPrivate:  subject.Reads(access.Private, product.ID),
				MayAssign:     triages && subject.Holds(access.Assigner, product.ID),
				MayTriage:     triages,
				TriagesPublic: subject.Triages(access.Public, product.ID),
				MayHide:       subject.Triages(access.Private, product.ID),
				// The capability, or a triage role — which is what the
				// operation accepts, and what makes a two-person team where
				// neither holds the capability able to review at all. Asked
				// of the capability alone, a screen drawing its controls
				// from this hides approve and reject from somebody the
				// server accepts, with nothing saying why.
				MayAgree:      agrees(access.Public) || agrees(access.Private),
				AgreesPublic:  agrees(access.Public),
				AgreesPrivate: agrees(access.Private),
				// Asked as the ruling store asks it: reading the reports, and
				// a right to agree that reaches undisclosed work.
				MayApproveRulings: subject.Reads(access.Private, product.ID) &&
					(subject.Holds(access.Approver, product.ID) ||
						subject.Triages(access.Private, product.ID)),
			})
		}
		sort.Slice(body.Reach, func(i, j int) bool {
			return body.Reach[i].Product < body.Reach[j].Product
		})
		return &struct{ Body WhoBody }{Body: body}, nil
	})
}
