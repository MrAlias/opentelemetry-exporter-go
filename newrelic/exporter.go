// Copyright 2019 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package newrelic contains an OpenTelemetry tracing exporter for New Relic.
package newrelic

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
	"go.opentelemetry.io/otel/api/core"
	export "go.opentelemetry.io/otel/sdk/export/metric"
	"go.opentelemetry.io/otel/sdk/export/metric/aggregator"
	"go.opentelemetry.io/otel/sdk/export/trace"
)

const (
	version          = "0.1.0"
	userAgentProduct = "NewRelic-Go-OpenTelemetry"
)

// Java implementation:
// https://github.com/newrelic/newrelic-opentelemetry-java-exporters/tree/master/src/main/java/com/newrelic/telemetry/opentelemetry/export

// Exporter exports spans to New Relic.
type Exporter struct {
	harvester *telemetry.Harvester
	// serviceName is the name of this service or application.
	serviceName string
}

var (
	errServiceNameEmpty = errors.New("service name is required")
)

// NewExporter creates a new Exporter that exports spans to New Relic.
func NewExporter(serviceName, apiKey string, options ...func(*telemetry.Config)) (*Exporter, error) {
	if serviceName == "" {
		return nil, errServiceNameEmpty
	}
	options = append([]func(*telemetry.Config){
		func(cfg *telemetry.Config) {
			cfg.Product = userAgentProduct
			cfg.ProductVersion = version
		},
		telemetry.ConfigAPIKey(apiKey),
	}, options...)
	h, err := telemetry.NewHarvester(options...)
	if nil != err {
		return nil, err
	}
	return &Exporter{
		harvester:   h,
		serviceName: serviceName,
	}, nil
}

var (
	_ interface {
		trace.SpanSyncer
		trace.SpanBatcher
		export.Exporter
	} = &Exporter{}
)

// Export exports multiple OpenTelemetry Instrument measurements to New Relic.
func (e *Exporter) Export(ctx context.Context, checkpoints export.CheckpointSet) error {
	var processErr error

	checkpoints.ForEach(func(record export.Record) {
		desc := record.Descriptor()
		agg := record.Aggregator()

		switch t := agg.(type) {
		case aggregator.Min:
			fmt.Printf("got Min/%s\n", desc.MetricKind().String())
			// TODO: summary?
		case aggregator.Max:
			fmt.Printf("got Max/%s\n", desc.MetricKind().String())
			// TODO: summary?
		case aggregator.Sum:
			rawSum, err := t.Sum()
			if err != nil {
				processErr = err
				return
			}
			e.harvester.MetricAggregator().Count(
				desc.Name(),
				map[string]interface{}{
					"service.name": e.serviceName,
					"description":  desc.Description(),
					"unit":         string(desc.Unit()),
				},
			).Increase(rawSum.AsFloat64())
		case aggregator.Count:
			fmt.Printf("got Count/%s\n", desc.MetricKind().String())
			// TODO: summary?
		case aggregator.MinMaxSumCount:
			fmt.Printf("got MinMaxSumCount/%s\n", desc.MetricKind().String())
			// TODO: summary
		case aggregator.LastValue:
			rawValue, timestamp, err := t.LastValue()
			if err != nil {
				processErr = err
				return
			}
			e.harvester.RecordMetric(telemetry.Gauge{
				Timestamp: timestamp,
				Value:     rawValue.AsFloat64(),
				Name:      desc.Name(),
				Attributes: map[string]interface{}{
					"service.name": e.serviceName,
					"description":  desc.Description(),
					"unit":         string(desc.Unit()),
				},
			})
		case aggregator.Quantile:
			fmt.Printf("got Quantile/%s\n", desc.MetricKind().String())
			// TODO: IDK?
		case aggregator.Points:
			fmt.Printf("got Points/%s\n", desc.MetricKind().String())
			// TODO: summary?
		default:
			fmt.Printf("got %s\n", desc.MetricKind().String())
			// TODO: return "unimplemented" error.
		}
	})

	return processErr
}

// ExportSpans exports multiple spans to New Relic.
func (e *Exporter) ExportSpans(ctx context.Context, spans []*trace.SpanData) {
	for _, s := range spans {
		e.ExportSpan(ctx, s)
	}
}

// ExportSpan exports a span to New Relic.
func (e *Exporter) ExportSpan(ctx context.Context, span *trace.SpanData) {
	if nil == e {
		return
	}
	e.harvester.RecordSpan(e.transformSpan(span))
}

func (e *Exporter) responseCodeIsError(code uint32) bool {
	if code == 0 {
		return false
	}
	return true
}

func transformSpanID(id core.SpanID) string {
	if !id.IsValid() {
		return ""
	}
	return hex.EncodeToString(id[:])
}

func (e *Exporter) makeAttributes(span *trace.SpanData) map[string]interface{} {
	isError := e.responseCodeIsError(uint32(span.Status))
	numAttrs := len(span.Attributes)
	if isError {
		numAttrs += 2
	}
	if 0 == numAttrs {
		return nil
	}
	attrs := make(map[string]interface{}, numAttrs)
	for _, pair := range span.Attributes {
		attrs[string(pair.Key)] = pair.Value.AsInterface()
	}
	if isError {
		attrs["error.code"] = uint32(span.Status)
		attrs["error.message"] = span.Status.String()
	}
	return attrs
}

// https://godoc.org/github.com/newrelic/newrelic-telemetry-sdk-go/telemetry#Span
// https://godoc.org/go.opentelemetry.io/otel/sdk/export/trace#SpanData
func (e *Exporter) transformSpan(span *trace.SpanData) telemetry.Span {
	return telemetry.Span{
		ID:          span.SpanContext.SpanIDString(),
		TraceID:     span.SpanContext.TraceIDString(),
		Timestamp:   span.StartTime,
		Name:        span.Name,
		ParentID:    transformSpanID(span.ParentSpanID),
		Duration:    span.EndTime.Sub(span.StartTime),
		ServiceName: e.serviceName,
		Attributes:  e.makeAttributes(span),
	}
}
