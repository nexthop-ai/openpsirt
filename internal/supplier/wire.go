// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier

// The two JSON files a publisher serves to say what they offer and where, as
// this reader reads them: the fields it uses and nothing else. A publisher
// writing a field it does not use in a shape the standard does not allow
// still has its listing read, which decoding into the whole shape this
// deployment writes would refuse. The names are the ones package csaf
// declares, which a test holds them to.

type providerMetadata struct {
	Distributions []distribution `json:"distributions"`
}

type distribution struct {
	DirectoryURL string `json:"directory_url,omitempty"`
	ROLIE        *rolie `json:"rolie,omitempty"`
}

type rolie struct {
	Feeds []feedDescription `json:"feeds"`
}

type feedDescription struct {
	TLPLabel string `json:"tlp_label"`
	URL      string `json:"url"`
}

type rolieFeed struct {
	Feed feedBody `json:"feed"`
}

type feedBody struct {
	Entries []feedEntry `json:"entry"`
}

type feedEntry struct {
	Links   []link  `json:"link"`
	Updated string  `json:"updated"`
	Content content `json:"content"`
}

type link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type content struct {
	Source string `json:"src"`
}
