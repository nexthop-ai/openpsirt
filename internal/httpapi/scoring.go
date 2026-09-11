package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func registerScoring(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "score-vector", Method: http.MethodGet, Path: "/v1/score",
		Summary: "Score a CVSS vector",
		Description: "Returns the base score and the severity band a vector works out to. " +
			"It reads nothing and records nothing.\n\n" +
			"CVSS 3.0 and 3.1 only. Version 4 has a different base formula and version 2 is a " +
			"different scheme, and scoring either with this one produces a number nothing " +
			"downstream could tell apart from a real one.",
		Tags: []string{"Findings"},
	}, anySubject, "Answers a calculation, and reads nothing."), func(ctx context.Context, input *struct {
		Vector string `query:"vector" required:"true" doc:"A CVSS 3.0 or 3.1 base vector"`
	}) (*struct {
		Body struct {
			Vector   string  `json:"vector" doc:"As it was read, upper-cased"`
			Score    float64 `json:"score"`
			Severity string  `json:"severity" enum:"none,low,medium,high,critical" doc:"The band the score falls in"`
		}
	}, error) {
		if _, err := reading(ctx); err != nil {
			return nil, err
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
				Score    float64 `json:"score"`
				Severity string  `json:"severity" enum:"none,low,medium,high,critical" doc:"The band the score falls in"`
			}
		}{}
		if scored != nil {
			out.Body.Vector = scored.Vector
			out.Body.Score = float64(scored.ScoreCenti) / 100
			out.Body.Severity = scored.Severity
		}
		return out, nil
	})
}
