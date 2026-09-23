package currency

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// mavenCentral asks Maven Central's repository, which is files rather than an
// API: a metadata document listing every version of an artifact, and a
// project document per version.
//
// Two requests where the other indexes take one. The metadata document names
// versions and nothing else, and the project document for the newest release
// is where its description and its address are written. What the repository
// says it last modified that document is the date, because a file there is
// never replaced once published.
type mavenCentral struct{ c *Client }

// mavenMetadata is the part of an artifact's metadata document read here.
//
// The document's own "release" field is not read. It names whatever was
// published last, which for a library releasing a new major line in betas is a
// beta — measured on log4j-core, it answers 3.0.0-beta3 while 2.25 is the
// newest release.
type mavenMetadata struct {
	Versions []string `xml:"versioning>versions>version"`
}

// mavenProject is the part of a project document read here.
type mavenProject struct {
	Name        string `xml:"name"`
	Description string `xml:"description"`
	URL         string `xml:"url"`
	SCM         struct {
		URL string `xml:"url"`
	} `xml:"scm"`
}

func (m mavenCentral) Latest(ctx context.Context, name string) (Latest, error) {
	group, artifact, ok := mavenCoordinates(name)
	if !ok {
		return Latest{}, fmt.Errorf("%w: %q is not a group and an artifact", ErrUnaskable, name)
	}
	base := m.c.Maven + "/maven2/" + group + "/" + artifact + "/"

	var metadata mavenMetadata
	if _, err := m.c.getXML(ctx, base+"maven-metadata.xml", &metadata); err != nil {
		return Latest{}, err
	}
	version := newest(vercmp.Maven, metadata.Versions)
	if version == "" {
		return Latest{}, ErrUnknown
	}
	latest := Latest{Version: version}

	// The project document is the second half, and the version is the useful
	// one. A document that will not come back leaves the row with a version
	// and nothing beside it, which is what the module proxy's answers look
	// like anyway.
	escaped := url.PathEscape(version)
	var project mavenProject
	header, err := m.c.getXML(ctx, base+escaped+"/"+artifact+"-"+escaped+".pom", &project)
	if err != nil {
		return latest, nil
	}
	if modified, err := http.ParseTime(header.Get("Last-Modified")); err == nil {
		latest.Released = modified.UTC()
	}
	latest.Summary = oneLine(firstOf(project.Description, project.Name))
	latest.Project = firstOf(project.URL, project.SCM.URL)
	return latest, nil
}

// mavenCoordinates reads a group and an artifact out of the name a package
// identifier gives, spelled as the repository lays them out: a directory per
// part of the group, then the artifact.
//
// A Maven identifier always has a group, so a name without one is refused. So
// is a part that would move the request somewhere else in the repository —
// empty, "." or "..".
func mavenCoordinates(name string) (group, artifact string, ok bool) {
	at := strings.LastIndex(name, "/")
	if at < 0 {
		return "", "", false
	}
	parts := strings.Split(name[:at], ".")
	for i, part := range parts {
		if !walkable(part) {
			return "", "", false
		}
		parts[i] = url.PathEscape(part)
	}
	artifact = name[at+1:]
	if !walkable(artifact) || strings.Contains(artifact, "/") {
		return "", "", false
	}
	return strings.Join(parts, "/"), url.PathEscape(artifact), true
}

// walkable says whether one part of a path names something rather than
// moving the request.
func walkable(part string) bool {
	return part != "" && part != "." && part != ".." && !strings.ContainsAny(part, "/\\")
}

// newest is the furthest along of the versions an index listed that is a
// release rather than one leading to a release, or the furthest along of all
// of them where none is.
//
// A version the scheme cannot read is passed over. It is somebody else's
// spelling in somebody else's index, and one of them leaving the whole answer
// empty would lose the version that could be read.
func newest(scheme vercmp.Scheme, versions []string) string {
	var best, bestAny string
	for _, each := range versions {
		each = strings.TrimSpace(each)
		leads, ok := vercmp.Leads(scheme, each)
		if !ok {
			continue
		}
		if further(scheme, each, bestAny) {
			bestAny = each
		}
		if !leads && further(scheme, each, best) {
			best = each
		}
	}
	return firstOf(best, bestAny)
}

// further says whether a version is further along than the best so far.
func further(scheme vercmp.Scheme, candidate, best string) bool {
	if best == "" {
		return true
	}
	c, ok := vercmp.Order(scheme, candidate, best)
	return ok && c > 0
}

// oneLine is the first line of what an index said, with its spacing
// collapsed. A project document's description is written inside markup, so it
// arrives indented and broken across lines.
func oneLine(said string) string {
	said = strings.TrimSpace(said)
	if at := strings.Index(said, "\n\n"); at >= 0 {
		said = said[:at]
	}
	return strings.Join(strings.Fields(said), " ")
}

// getXML reads an XML document, and the headers it came with.
//
// The decoder knows the five entities XML defines and fetches nothing, so a
// document referring to any other is refused as unreadable rather than
// expanded.
func (c *Client) getXML(ctx context.Context, at string, into any) (http.Header, error) {
	body, header, err := c.fetch(ctx, at, "application/xml")
	if err != nil {
		return nil, err
	}
	if err := xml.Unmarshal(body, into); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnaskable, at, err)
	}
	return header, nil
}
