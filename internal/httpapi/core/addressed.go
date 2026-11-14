// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import "github.com/nexthop-ai/openpsirt/internal/graph"

// BuildNamesBody names one build of a product, by the names that address it
// and as they were spelled, embedded in the answers that link to a build.
type BuildNamesBody struct {
	BranchOrTag     string `json:"branch_or_tag"`
	BranchOrTagName string `json:"branch_or_tag_name,omitempty" doc:"The branch or tag as it was spelled, or its name where no spelling was recorded"`
	Variant         string `json:"variant"`
	VariantName     string `json:"variant_name,omitempty" doc:"The variant as it was spelled, or its name where no spelling was recorded"`
}

// BuildNamed is one build a request or an answer names by its branch or tag
// and variant.
type BuildNamed struct {
	BranchOrTag string `json:"branch_or_tag" minLength:"1" doc:"A branch or a tag"`
	Variant     string `json:"variant" minLength:"1" doc:"The way that line is built"`
}

// PackageKindBody is the kind and namespace a component's package identifier
// names, embedded in the answers that tell two components of one name apart.
type PackageKindBody struct {
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package, as its identifier spells it"`
	Namespace string `json:"namespace,omitempty" doc:"The namespace its package identifier names, where it names one"`
}

// PackageKindOf reads the kind and namespace out of a package identifier.
func PackageKindOf(purl string) PackageKindBody {
	return PackageKindBody{Ecosystem: graph.EcosystemOf(purl), Namespace: graph.NamespaceOf(purl)}
}
