// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package csaf

import "time"

// Description is what a provider description is built from: where its files
// are, who publishes them, what aggregators may do with them, the keys that
// sign them, and the newest document's release.
type Description struct {
	// Metadata, Directory and Feed are the addresses of the description
	// itself, of the folder the documents sit in, and of the feed.
	Metadata, Directory, Feed string
	// Name is the publisher's name, as the feed is described by.
	Name string
	// TLP is the one label the documents carry.
	TLP       string
	Publisher Issuer
	Listed    bool
	Mirrored  bool
	// Keys is the keys every document is signed with, where they are. A
	// provider naming one claims the trusted provider role.
	Keys   []PublicKey
	Newest time.Time
}

// Describe is the provider description: one distribution that is both of the
// standard's shapes at once, year folders and a feed naming the same
// documents, dated from the newest document rather than the clock.
func Describe(d Description) ProviderMetadata {
	role := Provider
	if len(d.Keys) > 0 {
		role = TrustedProvider
	}
	return ProviderMetadata{
		CanonicalURL: d.Metadata,
		Distributions: []Distribution{{
			DirectoryURL: d.Directory,
			ROLIE: &ROLIE{Feeds: []FeedDescription{{
				Summary:  "Security documents " + d.Name + " publishes, TLP:" + d.TLP + ".",
				TLPLabel: d.TLP,
				URL:      d.Feed,
			}}},
		}},
		LastUpdated: Stamp(d.Newest),
		Listed:      d.Listed,
		Mirrored:    d.Mirrored,
		Version:     MetadataVersion,
		Publisher:   d.Publisher,
		PublicKeys:  d.Keys,
		Role:        role,
	}
}

// FeedTitle is the title of the one feed a publisher's documents of one label
// are listed in.
func FeedTitle(name, tlp string) string {
	return name + " CSAF documents (TLP:" + tlp + ")"
}
