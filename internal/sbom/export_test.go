package sbom

import "sort"

// VocabularyOverlap reports the top-level keys more than one format claims.
//
// The dispatch reads a key by the format that owns it, before the document has
// necessarily said which format it is — a producer sorting its keys puts one
// format's contents ahead of its own version statement, so requiring the
// declaration first would refuse documents that are well formed. That is only
// safe while no key means two things, which is a property of the tables rather
// than of anything a reader can check at run time.
func VocabularyOverlap() []string {
	claimed := map[string]int{}
	for _, vocabulary := range vocabularies {
		for key := range vocabulary {
			claimed[key]++
		}
	}
	var shared []string
	for key, times := range claimed {
		if times > 1 {
			shared = append(shared, key)
		}
	}
	sort.Strings(shared)
	return shared
}
