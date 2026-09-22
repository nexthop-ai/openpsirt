package supplier

// FetchForTest points the pass at a fetcher that answers without a network.
//
// Here rather than beside Pass, so it is not in the binary: the real fetcher
// reaches a publisher's own service, whose contents change, so the pass cannot
// be exercised end to end any other way — and a seam for that is not something
// a running deployment has a use for.
func FetchForTest(p *Pass, fetch *Fetcher) { p.fetch = fetch }
