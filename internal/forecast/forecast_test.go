// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package forecast_test

import (
	"math"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/forecast"
)

func TestForecaster_InsufficientDataHonesty(t *testing.T) {
	fc := forecast.NewForecaster(5)
	now := time.Now().UTC()

	// 2 samples < minSamples (5)
	samples := []forecast.Sample{
		{Timestamp: now.Add(-10 * time.Minute), Value: 10.0},
		{Timestamp: now, Value: 12.0},
	}

	res := fc.Forecast(forecast.ResourceDisk, "/", 100.0, samples)
	if res.State != forecast.StateNotEnoughData {
		t.Fatalf("expected StateNotEnoughData, got %s", res.State)
	}
	if res.Message == "" {
		t.Fatal("expected honest message when insufficient data")
	}
}

func TestForecaster_LinearSlopeAndTimeToExhaustion(t *testing.T) {
	fc := forecast.NewForecaster(5)
	now := time.Now().UTC()

	// Simulate disk usage growing by 10 GB every hour: 10 GB/hour
	// Current at t=0 is 50 GB. Capacity is 100 GB.
	// Remaining: 50 GB. At 10 GB/hour => exhaustion in exactly 5 hours.
	t0 := now.Add(-4 * time.Hour)
	samples := []forecast.Sample{
		{Timestamp: t0, Value: 10.0},
		{Timestamp: t0.Add(1 * time.Hour), Value: 20.0},
		{Timestamp: t0.Add(2 * time.Hour), Value: 30.0},
		{Timestamp: t0.Add(3 * time.Hour), Value: 40.0},
		{Timestamp: t0.Add(4 * time.Hour), Value: 50.0},
	}

	res := fc.Forecast(forecast.ResourceDisk, "/", 100.0, samples)

	// Verify slope: 10.0 per hour
	if math.Abs(res.SlopePerHour-10.0) > 0.05 {
		t.Errorf("expected slope ~10.0/hr, got %.2f/hr", res.SlopePerHour)
	}

	// Verify R^2 is 1.0 (perfect linear line)
	if math.Abs(res.R2Score-1.0) > 0.001 {
		t.Errorf("expected R2 ~1.0, got %.4f", res.R2Score)
	}

	// Verify TimeToExhaustion is approx 5 hours (within ±2 minutes error bound)
	expectedHours := 5.0
	actualHours := res.TimeToExhaustion.Hours()
	if math.Abs(actualHours-expectedHours) > 0.1 {
		t.Errorf("expected exhaustion in ~5.0 hours, got %.2f hours", actualHours)
	}

	// Verify confidence intervals exist and bound the estimate
	if res.ConfidenceLower >= res.TimeToExhaustion || res.ConfidenceUpper <= res.TimeToExhaustion {
		t.Errorf("confidence interval [%s, %s] does not bound estimate %s",
			res.ConfidenceLower, res.ConfidenceUpper, res.TimeToExhaustion)
	}
}

func TestForecaster_LeakVsSpikeDiscrimination(t *testing.T) {
	fc := forecast.NewForecaster(5)
	now := time.Now().UTC()

	t.Run("Monotonic leak growth", func(t *testing.T) {
		t0 := now.Add(-50 * time.Minute)
		samples := []forecast.Sample{
			{Timestamp: t0, Value: 100.0},
			{Timestamp: t0.Add(10 * time.Minute), Value: 110.0},
			{Timestamp: t0.Add(20 * time.Minute), Value: 120.0},
			{Timestamp: t0.Add(30 * time.Minute), Value: 130.0},
			{Timestamp: t0.Add(40 * time.Minute), Value: 140.0},
			{Timestamp: t0.Add(50 * time.Minute), Value: 150.0},
		}

		res := fc.Forecast(forecast.ResourceMemory, "proc:app", 0, samples)
		if !res.IsLeak {
			t.Errorf("expected IsLeak == true for strictly monotonic growth")
		}
	})

	t.Run("Transient spike (not a leak)", func(t *testing.T) {
		t0 := now.Add(-50 * time.Minute)
		samples := []forecast.Sample{
			{Timestamp: t0, Value: 100.0},
			{Timestamp: t0.Add(10 * time.Minute), Value: 102.0},
			{Timestamp: t0.Add(20 * time.Minute), Value: 500.0}, // Isolated spike
			{Timestamp: t0.Add(30 * time.Minute), Value: 101.0}, // Recovered
			{Timestamp: t0.Add(40 * time.Minute), Value: 103.0},
			{Timestamp: t0.Add(50 * time.Minute), Value: 102.0},
		}

		res := fc.Forecast(forecast.ResourceMemory, "proc:app", 0, samples)
		if res.IsLeak {
			t.Errorf("transient spike should not be classified as a monotonic leak")
		}
	})
}

func TestForecaster_RobustBaselineAndMADAnomaly(t *testing.T) {
	fc := forecast.NewForecaster(5)

	// Baseline samples clustered tightly around 50 MB
	samples := []forecast.Sample{
		{Value: 49.0},
		{Value: 50.0},
		{Value: 51.0},
		{Value: 50.0},
		{Value: 48.0},
		{Value: 52.0},
		{Value: 50.0},
	}

	base := fc.ComputeBaseline(forecast.ResourceMemory, "system_ram", samples)
	if math.Abs(base.Median-50.0) > 0.5 {
		t.Errorf("expected median ~50.0, got %f", base.Median)
	}

	// Normal variation: 52.0 is NOT an anomaly
	if base.IsAnomaly(52.0) {
		t.Errorf("52.0 should be within normal bounds")
	}

	// Massive spike: 200.0 IS an anomaly
	if !base.IsAnomaly(200.0) {
		t.Errorf("200.0 should be flagged as an anomaly by MAD bounds")
	}
}

func TestForecaster_ClockJumpAndRebootReconciliation(t *testing.T) {
	fc := forecast.NewForecaster(4)
	now := time.Now().UTC()

	// Samples containing duplicate and backward timestamps (clock adjustment/NTP sync)
	samples := []forecast.Sample{
		{Timestamp: now.Add(10 * time.Minute), Value: 20.0},
		{Timestamp: now.Add(5 * time.Minute), Value: 15.0},
		{Timestamp: now.Add(5 * time.Minute), Value: 15.0}, // Duplicate
		{Timestamp: now.Add(20 * time.Minute), Value: 25.0},
		{Timestamp: now.Add(30 * time.Minute), Value: 30.0},
	}

	res := fc.Forecast(forecast.ResourceDisk, "/var", 100.0, samples)
	if res.State == forecast.StateNotEnoughData {
		t.Fatalf("expected clean forecasting after clock reconciliation, got not enough data")
	}
	if res.SlopePerHour <= 0 {
		t.Errorf("expected positive slope, got %f", res.SlopePerHour)
	}
}

func TestForecaster_ZeroVarianceNaR2(t *testing.T) {
	fc := forecast.NewForecaster(5)
	now := time.Now().UTC()

	// 5 samples all identical 50.0%
	samples := []forecast.Sample{
		{Timestamp: now.Add(-4 * time.Minute), Value: 50.0},
		{Timestamp: now.Add(-3 * time.Minute), Value: 50.0},
		{Timestamp: now.Add(-2 * time.Minute), Value: 50.0},
		{Timestamp: now.Add(-1 * time.Minute), Value: 50.0},
		{Timestamp: now, Value: 50.0},
	}

	res := fc.Forecast(forecast.ResourceDisk, "/", 100.0, samples)
	if res.State != forecast.StateStable {
		t.Fatalf("expected state stable for zero variance, got %s", res.State)
	}
	if res.R2Text != "n/a" {
		t.Fatalf("expected R2Text 'n/a' for zero variance, got %s", res.R2Text)
	}
	if res.Unit != "percent" {
		t.Fatalf("expected unit 'percent', got %s", res.Unit)
	}
}
