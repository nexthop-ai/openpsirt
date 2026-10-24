// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// Placed is a run's documents read and placed in the checkout: what a run is
// held as until it is applied. The documents themselves are not kept.
type Placed struct {
	// Shape is the form the results are held in, which the release applying
	// them has to read. Any other JSON decodes as a run with no results, and
	// a comparable run with no results marks the whole build not reproduced.
	Shape   int            `json:"shape"`
	Results []sarif.Placed `json:"results,omitempty"`
	// RunOf is, per result, the run in Runs that reported it. What a run
	// says once is held once: a tool's name or a repository repeated per
	// result multiplies what an upload is held as by its result count.
	RunOf   []int                   `json:"run_of,omitempty"`
	Runs    []HeldRun               `json:"runs,omitempty"`
	Rules   map[string]finding.Rule `json:"rules,omitempty"`
	Modules []series.Module         `json:"modules,omitempty"`
	Signals int                     `json:"signals,omitempty"`
	Receipt Receipt                 `json:"receipt"`
}

// HeldRun is what one analyzer run of an upload says once for all its
// results.
type HeldRun struct {
	Tool string `json:"tool"`
	// Remotes is, per repository the run names, its address normalized.
	Remotes []string `json:"remotes,omitempty"`
}

// tool is the tool that reported result i.
func (p *Placed) tool(i int) string { return p.Runs[p.RunOf[i]].Tool }

// remote is the repository result i's file is in, or empty where it is in
// none the run names.
func (p *Placed) remote(i int) string {
	remotes, m := p.Runs[p.RunOf[i]].Remotes, p.Results[i].Module
	if m < 0 || m >= len(remotes) {
		return ""
	}
	return remotes[m]
}

// heldShape is the form this release holds placed results in.
const heldShape = 1

// Hold stores what a run is held as until it is applied, joining the
// caller's transaction. It is written as it is encoded, so the encoding is
// never in memory whole.
func (p Placed) Hold(ctx context.Context, store *series.Store, runID int64) error {
	r, w := io.Pipe()
	encoded := make(chan error, 1)
	go func() {
		err := p.encode(w)
		w.CloseWithError(err)
		encoded <- err
	}()
	_, err := store.Write(ctx, runID, 0, r)
	r.CloseWithError(errors.New("the placed results were not stored"))
	if held := <-encoded; err == nil && held != nil {
		err = fmt.Errorf("write the placed results: %w", held)
	}
	return err
}

// encode writes the placed results as JSON a result at a time. An encoder
// given the whole value builds all of it in memory before writing any.
func (p Placed) encode(w io.Writer) error {
	out := bufio.NewWriter(w)
	results := p.Results
	p.Shape, p.Results = heldShape, nil
	head, err := json.Marshal(p)
	if err != nil {
		return err
	}
	out.Write(head[:len(head)-1])
	out.WriteString(`,"results":[`)
	for i := range results {
		if i > 0 {
			out.WriteByte(',')
		}
		one, err := json.Marshal(&results[i])
		if err != nil {
			return err
		}
		if _, err := out.Write(one); err != nil {
			return err
		}
	}
	out.WriteString("]}")
	return out.Flush()
}

// decode reads placed results a result at a time, the form encode writes. A
// decoder given the whole value reads all of its bytes before decoding any.
func decode(r io.Reader) (Placed, error) {
	dec := json.NewDecoder(r)
	var out Placed
	if err := delim(dec, '{'); err != nil {
		return Placed{}, err
	}
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return Placed{}, err
		}
		field, _ := name.(string)
		if field != "results" {
			var into any
			switch field {
			case "shape":
				into = &out.Shape
			case "run_of":
				into = &out.RunOf
			case "runs":
				into = &out.Runs
			case "rules":
				into = &out.Rules
			case "modules":
				into = &out.Modules
			case "signals":
				into = &out.Signals
			case "receipt":
				into = &out.Receipt
			default:
				return Placed{}, fmt.Errorf("a field named %q", field)
			}
			if err := dec.Decode(into); err != nil {
				return Placed{}, err
			}
			continue
		}
		if err := delim(dec, '['); err != nil {
			return Placed{}, err
		}
		for dec.More() {
			var one sarif.Placed
			if err := dec.Decode(&one); err != nil {
				return Placed{}, err
			}
			out.Results = append(out.Results, one)
		}
		if err := delim(dec, ']'); err != nil {
			return Placed{}, err
		}
	}
	if err := delim(dec, '}'); err != nil {
		return Placed{}, err
	}
	if len(out.RunOf) != len(out.Results) {
		return Placed{}, errors.New("results and the runs that reported them differ in number")
	}
	for _, at := range out.RunOf {
		if at < 0 || at >= len(out.Runs) {
			return Placed{}, errors.New("a result names a run that is not held")
		}
	}
	return out, nil
}

// delim reads the next token, which has to be want.
func delim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("%v where %v was expected", t, want)
	}
	return nil
}

// held is what reading a run's placed results found: the results, or the
// failure that makes the run's ending.
type held struct {
	placed  Placed
	failure string
}

// failing remembers whether the reader under a decoder failed, which tells a
// fault reading the stored bytes from bytes this release does not read.
type failing struct {
	r   io.Reader
	err error
}

func (f *failing) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		f.err = err
	}
	return n, err
}

// read reads what a run is held as, decoding it as it is read. Results held
// in a shape this release does not read are the run's failure; a fault
// reading the stored bytes is returned.
func (a *Applier) read(ctx context.Context, store *series.Store, run *series.Run) (held, error) {
	docs, err := store.Documents(ctx, run.ID)
	if err != nil {
		return held{}, err
	}
	if len(docs) != 1 {
		return held{failure: "the run's placed results are not held"}, nil
	}
	in := &failing{r: store.Open(ctx, &docs[0])}
	out, err := decode(in)
	switch {
	case in.err != nil:
		return held{}, in.err
	case err != nil || out.Shape != heldShape:
		return held{failure: "the run's placed results could not be read"}, nil
	}
	return held{placed: out}, nil
}

// within refuses placed results larger than most once encoded. They are
// encoded into a count, so nothing of the encoding is held.
func within(p Placed, most int64) error {
	err := p.encode(&capped{most: most})
	if errors.Is(err, errPastBound) {
		return refusal.Errorf("the placed results come to more than the configured limit of %d bytes", most)
	}
	return err
}

// errPastBound is a count passing the bytes it may reach.
var errPastBound = errors.New("past the bound")

// capped counts what is written to it, and refuses past most.
type capped struct{ n, most int64 }

func (c *capped) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	if c.n > c.most {
		return 0, errPastBound
	}
	return len(p), nil
}
