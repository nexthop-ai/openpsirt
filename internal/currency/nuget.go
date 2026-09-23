package currency

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// nugetGallery asks nuget.org's registration document for a package, which
// lists every version with its date, its description and whether it is still
// listed.
//
// The registration kept for Semantic Versioning 2.0 and compressed, because
// the one without either leaves out every version spelled with a label that
// has a dot in it or build metadata — which for a package publishing
// "1.0.0-rc.1" is its pre-releases, and for some packages is every release.
//
// A registration is paged. A small one carries every page in the one
// document; a large one names the pages and each is its own request. Pages run
// oldest to newest, so they are read from the last back, and reading stops at
// the first holding a listed release.
type nugetGallery struct{ c *Client }

// nugetRegistration is a registration document, or one page of it.
type nugetRegistration struct {
	Items []nugetPage `json:"items"`
}

// nugetPage is one page: its own address, and its versions where the document
// carries them.
type nugetPage struct {
	ID    string      `json:"@id"`
	Items []nugetLeaf `json:"items"`
}

// nugetLeaf is one version.
type nugetLeaf struct {
	Entry struct {
		Version     string `json:"version"`
		Published   string `json:"published"`
		Listed      *bool  `json:"listed"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		ProjectURL  string `json:"projectUrl"`
	} `json:"catalogEntry"`
}

// nugetMostPages bounds how many pages one package costs. A package whose
// newest pages hold nothing but pre-releases would otherwise be read back to
// its first release, a request a page.
const nugetMostPages = 4

func (n nugetGallery) Latest(ctx context.Context, name string) (Latest, error) {
	if !walkable(name) {
		return Latest{}, fmt.Errorf("%w: %q is not a package name", ErrUnaskable, name)
	}
	// Lowered, because nuget.org serves every package under its name in lower
	// case and a name is matched without regard to case.
	base := n.c.NuGet + "/v3/registration5-gz-semver2/" + url.PathEscape(strings.ToLower(name)) + "/"
	var registration nugetRegistration
	if err := n.c.get(ctx, base+"index.json", &registration); err != nil {
		return Latest{}, err
	}

	var fallback *nugetLeaf
	fetched := 0
	for at := len(registration.Items) - 1; at >= 0; at-- {
		page := registration.Items[at]
		if page.Items == nil {
			if fetched == nugetMostPages {
				break
			}
			// The page's address is what the document says it is, so it is
			// held to the registration it came from: an answer naming a page
			// anywhere else is not followed.
			if !strings.HasPrefix(page.ID, base) {
				return Latest{}, fmt.Errorf("%w: a page of %q is at %q", ErrUnaskable, name, page.ID)
			}
			var read nugetPage
			if err := n.c.get(ctx, page.ID, &read); err != nil {
				return Latest{}, err
			}
			fetched++
			page = read
		}
		best, bestAny := nugetNewest(page.Items)
		if fallback == nil {
			fallback = bestAny
		}
		if best != nil {
			return best.latest(), nil
		}
	}
	if fallback != nil {
		return fallback.latest(), nil
	}
	return Latest{}, ErrUnknown
}

// nugetNewest is the furthest along of a page's listed versions that is a
// release, and the furthest along of all its listed versions.
//
// Listed only. A package its owner unlisted is one nuget.org stops offering
// to anybody choosing a version, and it dates every one of them to 1900.
func nugetNewest(leaves []nugetLeaf) (best, bestAny *nugetLeaf) {
	for i := range leaves {
		leaf := &leaves[i]
		if leaf.Entry.Listed != nil && !*leaf.Entry.Listed {
			continue
		}
		leads, ok := vercmp.Leads(vercmp.NuGet, leaf.Entry.Version)
		if !ok {
			continue
		}
		if bestAny == nil || further(vercmp.NuGet, leaf.Entry.Version, bestAny.Entry.Version) {
			bestAny = leaf
		}
		if !leads && (best == nil || further(vercmp.NuGet, leaf.Entry.Version, best.Entry.Version)) {
			best = leaf
		}
	}
	return best, bestAny
}

// latest is what one version says about the package.
//
// The summary where the package states one and its description where it does
// not, which on nuget.org is a paragraph rather than a README: the readme is
// a file of its own there.
func (l *nugetLeaf) latest() Latest {
	return Latest{
		Version:  l.Entry.Version,
		Released: released(l.Entry.Published),
		Summary:  oneLine(firstOf(l.Entry.Summary, l.Entry.Description)),
		Project:  l.Entry.ProjectURL,
	}
}

// released reads a date an index wrote, where the year is not a placeholder.
// nuget.org dates an unlisted version to 1900.
func released(text string) time.Time {
	at := parseTime(text)
	if at.Year() <= 1900 {
		return time.Time{}
	}
	return at
}
