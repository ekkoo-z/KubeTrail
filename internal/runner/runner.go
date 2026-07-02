package runner

import (
	"context"
	"os"
	"time"

	"github.com/ekkoo-z/KubeTrail/internal/collectors"
	"github.com/ekkoo-z/KubeTrail/internal/findings"
	"github.com/ekkoo-z/KubeTrail/internal/model"
	"github.com/ekkoo-z/KubeTrail/internal/sensitivity"
	"k8s.io/client-go/rest"
)

func Run(ctx context.Context, opts model.Options, version string) model.Document {
	return run(ctx, collectors.NewContext(opts), opts, version)
}

func RunWithKubeConfig(ctx context.Context, opts model.Options, version string, cfg *rest.Config, namespace string) model.Document {
	return run(ctx, collectors.NewContextWithKubeConfig(opts, cfg, namespace), opts, version)
}

func run(ctx context.Context, cctx *collectors.Context, opts model.Options, version string) model.Document {
	start := time.Now()
	hostname, _ := os.Hostname()

	target := model.TargetInfo{
		InKubernetes: cctx.InKubernetes(),
		Namespace:    cctx.Namespace(),
		PodName:      hostname,
		APIServer:    cctx.APIServer(),
	}
	if opts.RemoteOnly {
		target.InKubernetes = true
		target.PodName = ""
	}

	doc := model.Document{
		SchemaVersion: model.SchemaVersion,
		Run: model.RunInfo{
			ID:          start.UTC().Format("20060102T150405.000000000Z"),
			StartedAt:   start.UTC().Format(time.RFC3339Nano),
			Hostname:    hostname,
			ToolVersion: version,
			Args:        opts.Args,
		},
		Mode:   opts.Mode,
		Target: target,
	}

	for _, collector := range collectors.ForOptions(opts) {
		select {
		case <-ctx.Done():
			doc.Errors = append(doc.Errors, model.ErrorEntry{
				Message: ctx.Err().Error(),
			})
			finalize(&doc, start, opts.SensitiveMode, opts.Scans)
			return doc
		default:
		}

		cr := runCollector(ctx, cctx, collector)
		doc.Facts = append(doc.Facts, cr.Facts...)
		doc.Errors = append(doc.Errors, cr.Errors...)
		cr.Facts = nil
		doc.Collectors = append(doc.Collectors, cr)
	}

	finalize(&doc, start, opts.SensitiveMode, opts.Scans)
	return doc
}

func RunServiceAccountTokenAudit(ctx context.Context, opts model.Options, version string) model.SATokenAuditDocument {
	cctx := collectors.NewContext(opts)
	return collectors.CollectServiceAccountTokenAudit(ctx, cctx, version)
}

func runCollector(ctx context.Context, cctx *collectors.Context, collector collectors.Collector) model.CollectorResult {
	start := time.Now()
	result := model.CollectorResult{
		ID:          collector.ID(),
		Mode:        collector.Mode(),
		SideEffects: collector.SideEffects(),
		Status:      "ok",
	}

	facts, errs := collector.Collect(ctx, cctx)
	result.Facts = facts
	result.FactCount = len(facts)
	result.Errors = errs
	result.DurationMs = time.Since(start).Milliseconds()

	for i := range result.Facts {
		result.Facts[i].Collector = collector.ID()
		if result.Facts[i].ID == "" {
			result.Facts[i].ID = collector.ID() + ".fact"
		}
	}
	for i := range result.Errors {
		if result.Errors[i].Collector == "" {
			result.Errors[i].Collector = collector.ID()
		}
	}

	if len(errs) > 0 && len(facts) > 0 {
		result.Status = "partial"
	} else if len(errs) > 0 {
		result.Status = "error"
	} else if len(facts) == 0 {
		result.Status = "skipped"
	}
	return result
}

func finalize(doc *model.Document, start time.Time, sensitiveMode model.SensitiveMode, scans []string) {
	finished := time.Now()
	doc.Run.FinishedAt = finished.UTC().Format(time.RFC3339Nano)
	doc.Run.DurationMs = finished.Sub(start).Milliseconds()
	sensitivity.Apply(doc, sensitiveMode)
	doc.Findings = findings.Evaluate(*doc, scans)
	if doc.Findings == nil {
		doc.Findings = []model.Finding{}
	}
	findings.SortBySeverity(doc.Findings)
}
