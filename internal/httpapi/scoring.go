package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func registerScoring(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "score-vector", Method: http.MethodGet, Path: "/v1/score",
		Summary: "Score a CVSS vector",
		Description: "Returns the base score and the severity band a vector works out to. " +
			"It reads nothing and records nothing.\n\n" +
			"An empty vector is refused rather than answered with empty fields.\n\n" +
			"CVSS 3.0, 3.1 and 4.0. A vector on any other scheme is refused, including " +
			"version 2. Metrics outside the base set are read and ignored, so a vector " +
			"carrying threat or environmental metrics scores as the base vector in it.\n\n" +
			"Scores from two schemes are not comparable as numbers. The severity band is, " +
			"and it is the same five words over the same five ranges under both.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers a calculation, and reads nothing."), func(ctx context.Context, input *struct {
		Vector string `query:"vector" required:"true" doc:"A CVSS 3.0, 3.1 or 4.0 base vector"`
	}) (*struct {
		Body struct {
			Vector   string  `json:"vector" doc:"As it was read, upper-cased"`
			Version  string  `json:"version" doc:"The scheme the vector is on"`
			Score    float64 `json:"score"`
			Severity string  `json:"severity" enum:"none,low,medium,high,critical" doc:"The band the score falls in"`
		}
	}, error) {
		if _, err := reading(ctx); err != nil {
			return nil, err
		}
		// An empty vector is the caller's to fix. Required checks that the
		// parameter is present rather than that it says anything, and scoring
		// nothing answers nothing — which would leave every field of the
		// reply empty, including a severity this operation's own enumeration
		// has no word for.
		if strings.TrimSpace(input.Vector) == "" {
			return nil, asked(in.Logger,
				fmt.Errorf("%w: state a vector to score", finding.ErrNotAVector))
		}
		scored, err := finding.Score(input.Vector)
		if errors.Is(err, finding.ErrNotAVector) {
			return nil, asked(in.Logger, err)
		}
		if err != nil {
			return nil, refused(in.Logger, err, "that could not be scored")
		}
		out := &struct {
			Body struct {
				Vector   string  `json:"vector" doc:"As it was read, upper-cased"`
				Version  string  `json:"version" doc:"The scheme the vector is on"`
				Score    float64 `json:"score"`
				Severity string  `json:"severity" enum:"none,low,medium,high,critical" doc:"The band the score falls in"`
			}
		}{}
		out.Body.Vector = scored.Vector
		out.Body.Version = scored.Scheme()
		out.Body.Score = float64(scored.ScoreCenti) / 100
		out.Body.Severity = scored.Severity
		return out, nil
	})
}
