package httpapi_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

func TestEveryLimitOfferedIsOneTheStoresKnow(t *testing.T) {
	// The bound is stated twice by design: the API declares it on the
	// parameter, so a caller asking for too much is told the number, and the
	// store clamps, so a caller that is not the API — a background pass, a
	// test, a second surface — cannot ask for the whole table. Two statements
	// of one number drift, and these had: six pairs across twenty-two reads
	// with nothing saying which list gets which, and one endpoint declaring a
	// ceiling its own store did not share.
	//
	// The stores name their pages now, so this checks the declarations are
	// drawn from the same short list rather than typed.
	known := map[[2]int]string{}
	for name, page := range map[string]database.Page{
		"AList":            database.AList,
		"InBulk":           database.InBulk,
		"AWholeBuild":      database.AWholeBuild,
		"AComponentsWorth": database.AComponentsWorth,
		"APlot":            database.APlot,
		"APicker":          database.APicker,
	} {
		known[[2]int{page.ByDefault, page.Most}] = name
	}

	twoReach(t, func(t *testing.T, r *reach) {
		var checked int
		for path, item := range r.api.OpenAPI().Paths {
			if item.Get == nil {
				continue
			}
			for _, param := range item.Get.Parameters {
				if param.Name != "limit" || param.Schema == nil {
					continue
				}
				byDefault, most := 0, 0
				if n, ok := param.Schema.Default.(int); ok {
					byDefault = n
				}
				if param.Schema.Maximum != nil {
					most = int(*param.Schema.Maximum)
				}
				checked++
				if _, held := known[[2]int{byDefault, most}]; !held {
					t.Errorf("GET %s offers up to %d and %d by default, which is no page "+
						"any store names", path, most, byDefault)
				}
			}
		}
		if checked < 15 {
			t.Fatalf("only %d endpoints declare a limit: this is not walking the API", checked)
		}
	})
}
