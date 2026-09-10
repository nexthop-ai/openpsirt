package signin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// GitHub signs somebody in through GitHub's OAuth 2.0.
//
// A separate adapter because GitHub is not an OpenID Connect provider: it
// issues no identity token and publishes no discovery document, so there is
// nothing to verify and the account has to be asked for instead. What comes
// back is an opaque token this API could not check by itself, which is also
// why the browser never holds one.
type GitHub struct {
	config oauth2.Config
	client *http.Client
	// organization bounds whose teams count as groups. Without it every team
	// in every organization somebody belongs to would map to roles here.
	organization string
}

// GitHubConfig is what an operator supplies for GitHub sign-in.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	// Organization is whose teams bind to roles. Empty means groups are not
	// read at all, which is the right answer for a deployment assigning roles
	// directly.
	Organization string
}

// gitHubAPI and gitHubAuth are where this talks to, and the only hosts it may.
const (
	gitHubAPI  = "api.github.com"
	gitHubAuth = "github.com"
)

// NewGitHub returns an adapter for GitHub sign-in.
func NewGitHub(cfg GitHubConfig) (*GitHub, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("github sign-in needs a client identifier and secret")
	}

	// read:org is asked for only where teams are actually bound to roles.
	// Asking for it otherwise puts a scope on the consent screen that this
	// deployment has no use for, which is how people learn to approve scopes
	// without reading them.
	scopes := []string{"read:user", "user:email"}
	if cfg.Organization != "" {
		scopes = append(scopes, "read:org")
	}

	return &GitHub{
		config: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			Endpoint: github.Endpoint, Scopes: scopes,
		},
		client:       outward.Guarded(gitHubAPI, gitHubAuth),
		organization: cfg.Organization,
	}, nil
}

// Name is how a sign-in path names this provider.
func (g *GitHub) Name() string { return "github" }

// Begin returns where to send the browser.
func (g *GitHub) Begin(_ context.Context, redirectURI string) (string, Pending, error) {
	pending, err := newPending()
	if err != nil {
		return "", Pending{}, err
	}
	config := g.config
	config.RedirectURL = redirectURI

	return config.AuthCodeURL(pending.State,
		oauth2.SetAuthURLParam("code_challenge", pending.challenge()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), pending, nil
}

// Complete exchanges the code and asks GitHub who this is.
func (g *GitHub) Complete(ctx context.Context, code string, pending Pending, redirectURI string) (*Identity, error) {
	config := g.config
	config.RedirectURL = redirectURI

	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	token, err := config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pending.Verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange what github sent back: %w", err)
	}

	var account struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := g.get(ctx, token, "https://api.github.com/user", &account); err != nil {
		return nil, err
	}
	username, err := usernameFrom(account.Login)
	if err != nil {
		return nil, err
	}

	identity := &Identity{
		// The numeric identifier rather than the login: a login can be changed
		// by its owner and then taken by somebody else, and matching on it
		// would eventually hand one person's access to another.
		Subject:     strconv.FormatInt(account.ID, 10),
		Username:    username,
		DisplayName: account.Name,
	}
	// The address on the profile is whatever somebody chose to show publicly,
	// and often nothing at all. The verified ones are a list of their own, and
	// the scope to read it is already asked for — so the address this hands
	// over is the primary verified one or none, rather than a public string
	// nobody checked.
	if address, ok := g.verifiedEmail(ctx, token); ok {
		identity.Email, identity.EmailVerified = address, true
	}
	if g.organization != "" {
		identity.Groups, err = g.teams(ctx, token)
		if err != nil {
			return nil, err
		}
	}
	return identity, nil
}

// teams reads the organization teams somebody belongs to.
//
// An organization can restrict which OAuth applications may see membership. If
// it has, this comes back empty rather than failing — so a deployment binding
// roles to teams would admit nobody at all rather than admitting everybody,
// which is the direction to fail in.
func (g *GitHub) teams(ctx context.Context, token *oauth2.Token) ([]string, error) {
	// Paged through rather than read once. This endpoint reports teams across
	// every organization somebody belongs to, so a single page is not a page
	// of *our* teams — and truncating it would silently strip roles from
	// whoever happens to be in a lot of teams, which is a refusal nobody could
	// diagnose from either side.
	names := []string{}
	for page := 1; page <= maxTeamPages; page++ {
		var memberships []struct {
			Slug         string `json:"slug"`
			Organization struct {
				Login string `json:"login"`
			} `json:"organization"`
		}
		url := fmt.Sprintf("https://api.github.com/user/teams?per_page=%d&page=%d", teamPageSize, page)
		if err := g.get(ctx, token, url, &memberships); err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			if membership.Organization.Login != g.organization {
				continue
			}
			names = append(names, membership.Slug)
		}
		if len(memberships) < teamPageSize {
			return names, nil
		}
	}
	// More pages than anybody reasonably has. Reported rather than truncated:
	// a silently short list would withdraw roles, and doing that without
	// saying so is the failure this whole path is written to avoid.
	return nil, fmt.Errorf("github reports more than %d pages of teams, which is more than this reads",
		maxTeamPages)
}

// How much of GitHub's team listing is read. The page size is its maximum, and
// the page limit is a bound on an answer that should never be near it.
const (
	teamPageSize = 100
	maxTeamPages = 20
)

// get asks GitHub something, through the client that will talk to GitHub and
// nowhere else.
func (g *GitHub) get(ctx context.Context, token *oauth2.Token, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("ask github: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("ask github: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github answered %s", resp.Status)
	}
	// Bounded, because what is being decoded arrives over the network from
	// somewhere this process was configured to trust rather than somewhere it
	// controls. A profile is a few hundred bytes; a body that never ends is a
	// sign-in that allocates until the process dies, and the whole point of
	// the guarded client is that an outbound fetch cannot be turned into a way
	// in.
	if err := json.NewDecoder(io.LimitReader(resp.Body, mostFromGitHub)).
		Decode(into); err != nil {
		return fmt.Errorf("read what github answered: %w", err)
	}
	return nil
}

// mostFromGitHub is how much of an answer is read before it is a problem
// rather than a profile. Generous against the few hundred bytes a profile or
// an address list actually is.
const mostFromGitHub = 1 << 20

// verifiedEmail asks for the addresses GitHub has confirmed and returns the
// primary one.
//
// A failure is not a failure to sign in. Somebody arriving is what was asked
// for; where to reach them later is not part of it, and refusing the first
// because the second did not answer would lock people out over a column.
func (g *GitHub) verifiedEmail(ctx context.Context, token *oauth2.Token) (string, bool) {
	var addresses []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.get(ctx, token, "https://api.github.com/user/emails", &addresses); err != nil {
		return "", false
	}
	fallback := ""
	for _, address := range addresses {
		if !address.Verified || strings.TrimSpace(address.Email) == "" {
			continue
		}
		if address.Primary {
			return address.Email, true
		}
		if fallback == "" {
			fallback = address.Email
		}
	}
	return fallback, fallback != ""
}
