// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// RepositoryHost is a repository host a product's links may point at.
type RepositoryHost struct {
	Remote          string               `json:"remote" doc:"The remotes the host covers: a host such as github.com, or a host and the path a mirror keeps its copies under"`
	Web             string               `json:"web" doc:"The https address the covered repositories are under, which links open on"`
	Style           core.RepositoryStyle `json:"style" doc:"The kind of server, which names the addresses it writes; custom takes the two templates"`
	FileTemplate    string               `json:"file_template,omitempty" doc:"For a custom host, a file's lines: begins with {repo}/ and may name {commit}, {path}, {start} and {end}"`
	CompareTemplate string               `json:"compare_template,omitempty" doc:"For a custom host, two commits compared: begins with {repo}/ and may name {from} and {to}"`
}

// RepositoryPath is what a product says about the code under a path prefix.
type RepositoryPath struct {
	Prefix   string `json:"prefix" doc:"A path from the top of the checkout. Empty is the whole product"`
	Remote   string `json:"remote,omitempty" doc:"The repository the code under the prefix is, where an upload names none. Sent with branch"`
	Branch   string `json:"branch,omitempty" doc:"The branch links into that repository open on. Such links are approximate"`
	Snippets *bool  `json:"snippets,omitempty" doc:"Whether source snippets under the prefix are kept. Absent takes the nearest prefix that states it, and no prefix stating it keeps them. False at the empty prefix turns them off for the product"`
	// DisclosedSnippets is apart from Snippets: keeping source to read here
	// and publishing it beside an advisory are two decisions.
	DisclosedSnippets *bool `json:"disclosed_snippets,omitempty" doc:"Whether the snippets of a code finding included in its flaw's disclosure are disclosed with its flaw. Absent takes the nearest prefix that states it, and no prefix stating it strips them at disclosure"`
}

// RepositoriesBody is what a product says about its repositories.
type RepositoriesBody struct {
	Hosts []RepositoryHost `json:"hosts" doc:"The repository hosts locations may link to. A repository on no host here is shown unlinked"`
	Paths []RepositoryPath `json:"paths" doc:"What the product says about the code under each path prefix"`
}

func registerCatalogRepositories(api huma.API, d core.Declaring) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-product-repositories", Method: http.MethodGet,
		Path:    "/v1/products/{product}/repositories",
		Summary: "Get a product's repository settings",
		Description: "Returns the repository hosts a product's source links may point at, and what it says " +
			"about the code under each path prefix: the repository and branch for paths an upload names " +
			"no repository for, and whether source snippets are kept.",
		Tags: []string{"Catalog"},
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
	}) (*struct{ Body RepositoriesBody }, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		_, product, err := core.ProductIn(ctx, d, d.DB.DB, in.Product)
		if err != nil {
			return nil, err
		}
		held, err := sourcelink.NewStore(d.DB.DB).Config(ctx, product.ID)
		if err != nil {
			return nil, core.WentWrong(d.Logger, "the repository settings could not be read", err)
		}
		return &struct{ Body RepositoriesBody }{Body: repositoriesSaid(held)}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "set-product-repositories", Method: http.MethodPut,
		Path:    "/v1/products/{product}/repositories",
		Summary: "Set a product's repository settings",
		Description: "Replaces the repository hosts a product's source links may point at, and what it says " +
			"about the code under each path prefix. Links are built when a location is read, so a change " +
			"reaches every location at once. Snippets are kept or discarded as an upload arrives, so a " +
			"change reaches the uploads after it.\n\n" +
			"Refused, naming the entry, where a host is not https, a template does not begin at the " +
			"repository or names a placeholder it may not, an entry is named twice, a repository is sent " +
			"without its branch, or a path climbs out of the checkout. Recorded in the administrative trail.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    RepositoriesBody
	}) (*struct{}, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		stated := repositoriesStated(in.Body)
		if err := stated.Valid(); err != nil {
			return nil, huma.Error422UnprocessableEntity(err.Error())
		}
		return &struct{}{}, core.Changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			_, product, err := core.ProductIn(ctx, d, tx, in.Product)
			if err != nil {
				return err
			}
			store := sourcelink.NewStore(tx)
			was, err := store.Config(ctx, product.ID)
			if err != nil {
				return core.WentWrong(d.Logger, "the repository settings could not be read", err)
			}
			err = store.Replace(ctx, product.ID, stated)
			var refused refusal.Refusal
			switch {
			case errors.As(err, &refused):
				return huma.Error422UnprocessableEntity(err.Error())
			case err != nil:
				return core.WentWrong(d.Logger, "the repository settings could not be recorded", err)
			}
			before, after := said(repositoriesSaid(was)), said(repositoriesSaid(stated))
			if err := core.Noted(ctx, tx, trail.Setting, "repositories of "+product.Name,
				trail.Said(before, true), trail.Said(after, true)); err != nil {
				return core.NotRecorded(d.Logger, err)
			}
			return nil
		})
	})
}

// repositoriesStated is a request's settings in the form they are checked
// and stored in.
func repositoriesStated(b RepositoriesBody) sourcelink.Config {
	var c sourcelink.Config
	for _, h := range b.Hosts {
		c.Hosts = append(c.Hosts, sourcelink.Host{
			Remote: h.Remote, Web: h.Web, Style: sourcelink.Style(h.Style),
			FileTemplate: h.FileTemplate, CompareTemplate: h.CompareTemplate,
		})
	}
	for _, p := range b.Paths {
		c.Paths = append(c.Paths, sourcelink.Path{Prefix: p.Prefix, Remote: p.Remote, Branch: p.Branch,
			Snippets: p.Snippets, DisclosedSnippets: p.DisclosedSnippets})
	}
	return c
}

// repositoriesSaid is a product's settings as an answer states them.
func repositoriesSaid(c sourcelink.Config) RepositoriesBody {
	out := RepositoriesBody{Hosts: []RepositoryHost{}, Paths: []RepositoryPath{}}
	for _, h := range c.Hosts {
		out.Hosts = append(out.Hosts, RepositoryHost{
			Remote: h.Remote, Web: h.Web, Style: core.RepositoryStyle(h.Style),
			FileTemplate: h.FileTemplate, CompareTemplate: h.CompareTemplate,
		})
	}
	for _, p := range c.Paths {
		out.Paths = append(out.Paths, RepositoryPath{Prefix: p.Prefix, Remote: p.Remote, Branch: p.Branch,
			Snippets: p.Snippets, DisclosedSnippets: p.DisclosedSnippets})
	}
	return out
}

// said is the settings as the trail records them.
func said(b RepositoriesBody) string {
	out, _ := json.Marshal(b)
	return string(out)
}
