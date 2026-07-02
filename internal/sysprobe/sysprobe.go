package sysprobe

import (
	"context"
)

type Result struct {
	Name     string `json:"name"`
	Allowed  bool   `json:"allowed"`
	Errno    string `json:"errno,omitempty"`
	Error    string `json:"error,omitempty"`
	Duration int64  `json:"durationMs"`
}

func RunMatrix(ctx context.Context) []Result {
	names := ProbeNames()
	results := make([]Result, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			results = append(results, Result{Name: name, Error: err.Error()})
			continue
		}
		results = append(results, RunOne(name))
	}
	return results
}
