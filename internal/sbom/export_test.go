package sbom

import "sort"

// VocabularyOverlap reports the top-level keys more than one format claims.
//
// The dispatch reads a key by the format that owns it, before the document has
// necessarily said which format it is — a producer sorting its keys puts one
// format's contents ahead of its own version statement, so requiring the
// declaration first would refuse documents that are well formed. Two
// vocabularies claiming one key would make that routing a coin toss, which is
// a property of the tables rather than of anything a reader can check at run
// time.
//
// Keys shared by two tables of the *same* format are not an overlap: which of
// them a key belongs to is not a question anybody has to answer.
func VocabularyOverlap() []string {
	claimed := map[string]map[Format]bool{}
	for _, v := range vocabularies {
		for key := range v.top {
			if claimed[key] == nil {
				claimed[key] = map[Format]bool{}
			}
			claimed[key][v.format] = true
		}
	}
	var shared []string
	for key, formats := range claimed {
		if len(formats) > 1 {
			shared = append(shared, key)
		}
	}
	sort.Strings(shared)
	return shared
}
