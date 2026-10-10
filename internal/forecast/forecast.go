// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package forecast

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Sample represents a timestamped resource measurement.
type Sample struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// ResourceKind represents the target resource being tracked and forecasted.
type ResourceKind string

const (
	ResourceDisk   ResourceKind = "disk"
	ResourceMemory ResourceKind = "memory"
	ResourceInodes ResourceKind = "inodes"
	ResourceFDs    ResourceKind = "fds"
	ResourceSwap   ResourceKind = "swap"
	ResourceLoad   ResourceKind = "load"
)

// State indicates the validity or condition of the forecast.
type State string

const (
	StateOK             State = "ok"
	StateNotEnoughData  State = "not_enough_data"
	StateStable         State = "stable"
	StateExhaustionRisk State = "exhaustion_risk"
	StateLeakDetected   State = "leak_detected"
	StateAnomaly        State = "anomaly"
)

// Result represents the forecasted trend and exhaustion estimation for a resource.
type Result struct {
	Resource         ResourceKind  `json:"resource"`
	Target           string        `json:"target"` // e.g. "/", "system_ram", "proc:nginx"
	State            State         `json:"state"`
	Message          string        `json:"message"`
	CurrentValue     float64       `json:"current_value"`
	Capacity         float64       `json:"capacity,omitempty"`
	SlopePerHour     float64       `json:"slope_per_hour"` // Rate of change per hour
	R2Score          float64       `json:"r2_score"`       // Coefficient of determination
	TimeToExhaustion time.Duration `json:"time_to_exhaustion,omitempty"`
	ConfidenceLower  time.Duration `json:"confidence_lower,omitempty"`
	ConfidenceUpper  time.Duration `json:"confidence_upper,omitempty"`
	IsLeak           bool          `json:"is_leak"`
	IsAnomaly        bool          `json:"is_anomaly"`
	SampleCount      int           `json:"sample_count"`
}

// Baseline represents robust rolling baseline statistics (Median and MAD) for anomaly detection.
type Baseline struct {
	Resource  ResourceKind `json:"resource"`
	Target    string       `json:"target"`
	Median    float64      `json:"median"`
	MAD       float64      `json:"mad"` // Median Absolute Deviation
	LowerNorm float64      `json:"lower_norm"`
	UpperNorm float64      `json:"upper_norm"`
	Samples   int          `json:"samples"`
}

// Forecaster executes deterministic statistical forecasting without ML.
type Forecaster struct {
	minSamples int
}

// NewForecaster creates a new forecaster.
func NewForecaster(minSamples int) *Forecaster {
	if minSamples <= 0 {
		minSamples = 5
	}
	return &Forecaster{minSamples: minSamples}
}

// Forecast performs linear regression, leak detection, and exhaustion estimation on samples.
// Enforces honest "not enough data" state when samples are insufficient.
// Handles clock-jumps and reboots gracefully.
func (f *Forecaster) Forecast(resource ResourceKind, target string, capacity float64, samples []Sample) Result {
	res := Result{
		Resource:    resource,
		Target:      target,
		Capacity:    capacity,
		SampleCount: len(samples),
	}

	if len(samples) < f.minSamples {
		res.State = StateNotEnoughData
		res.Message = fmt.Sprintf("Not enough historical data (%d/%d samples) to calculate forecast.", len(samples), f.minSamples)
		if len(samples) > 0 {
			res.CurrentValue = samples[len(samples)-1].Value
		}
		return res
	}

	// Filter and sort samples chronologically, handling any clock-jumps
	sorted := make([]Sample, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	// Detect reboots or clock-jumps: discard samples if timestamps are equal
	var clean []Sample
	for i := 0; i < len(sorted); i++ {
		if i > 0 && !sorted[i].Timestamp.After(sorted[i-1].Timestamp) {
			continue // Skip backward or identical timestamps (clock adjustments)
		}
		clean = append(clean, sorted[i])
	}

	if len(clean) < f.minSamples {
		res.State = StateNotEnoughData
		res.Message = "Insufficient valid time-ordered samples after clock-jump reconciliation."
		return res
	}

	res.CurrentValue = clean[len(clean)-1].Value

	// Linear Regression (Ordinary Least Squares)
	// x in seconds from start
	t0 := clean[0].Timestamp
	var (
		sumX  float64
		sumY  float64
		sumXY float64
		sumX2 float64
		n     = float64(len(clean))
	)

	for _, s := range clean {
		x := s.Timestamp.Sub(t0).Seconds()
		y := s.Value
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	denom := (n*sumX2 - sumX*sumX)
	if math.Abs(denom) < 1e-9 {
		res.State = StateStable
		res.Message = "Resource usage is stable with zero variance over time."
		return res
	}

	slopePerSec := (n*sumXY - sumX*sumY) / denom
	intercept := (sumY - slopePerSec*sumX) / n
	slopePerHour := slopePerSec * 3600.0
	res.SlopePerHour = slopePerHour

	// Compute R^2 Score
	yMean := sumY / n
	var ssTot, ssRes float64
	for _, s := range clean {
		x := s.Timestamp.Sub(t0).Seconds()
		yPred := slopePerSec*x + intercept
		ssTot += (s.Value - yMean) * (s.Value - yMean)
		ssRes += (s.Value - yPred) * (s.Value - yPred)
	}

	if ssTot > 1e-9 {
		res.R2Score = math.Max(0.0, 1.0-(ssRes/ssTot))
	} else {
		res.R2Score = 1.0 // Identical points
	}

	// Leak Detection: strictly monotonic non-decreasing with consistent positive growth
	isMonotonic := true
	for i := 1; i < len(clean); i++ {
		if clean[i].Value < clean[i-1].Value {
			isMonotonic = false
			break
		}
	}
	if isMonotonic && slopePerHour > 0.001 {
		res.IsLeak = true
	}

	// Time to Exhaustion
	if capacity > 0 && slopePerSec > 0 {
		remaining := capacity - res.CurrentValue
		if remaining <= 0 {
			res.State = StateExhaustionRisk
			res.TimeToExhaustion = 0
			res.Message = "Resource capacity fully exhausted or exceeded."
			return res
		}

		secsToFull := remaining / slopePerSec
		res.TimeToExhaustion = time.Duration(secsToFull) * time.Second

		// Confidence interval based on slope variance (bounds: ±20% slope variation)
		lowerSecs := remaining / (slopePerSec * 1.25)
		upperSecs := remaining / (slopePerSec * 0.75)
		res.ConfidenceLower = time.Duration(lowerSecs) * time.Second
		res.ConfidenceUpper = time.Duration(upperSecs) * time.Second

		if res.TimeToExhaustion < 72*time.Hour {
			res.State = StateExhaustionRisk
			res.Message = fmt.Sprintf("Exhaustion predicted in %s (rate: %.2f/hr)", formatExhaustionDuration(res.TimeToExhaustion), slopePerHour)
		} else {
			res.State = StateOK
			res.Message = fmt.Sprintf("Growth rate is stable (exhaustion in %s)", formatExhaustionDuration(res.TimeToExhaustion))
		}
	} else if res.IsLeak {
		res.State = StateLeakDetected
		res.Message = fmt.Sprintf("Monotonic growth detected (slope: +%.2f/hr), potential resource leak.", slopePerHour)
	} else {
		res.State = StateStable
		res.Message = "Resource usage is stable or declining."
	}

	return res
}

// ComputeBaseline calculates robust non-parametric Median and MAD statistics.
// No machine learning, robust against single-point outlier spikes.
func (f *Forecaster) ComputeBaseline(resource ResourceKind, target string, samples []Sample) Baseline {
	base := Baseline{
		Resource: resource,
		Target:   target,
		Samples:  len(samples),
	}

	if len(samples) == 0 {
		return base
	}

	vals := make([]float64, len(samples))
	for i, s := range samples {
		vals[i] = s.Value
	}
	sort.Float64s(vals)

	base.Median = median(vals)

	// Calculate absolute deviations from median
	devs := make([]float64, len(vals))
	for i, v := range vals {
		devs[i] = math.Abs(v - base.Median)
	}
	sort.Float64s(devs)
	base.MAD = median(devs)

	// Standard normal consistency factor for MAD is 1.4826
	// 3-sigma equivalent bounds: median ± 3 * 1.4826 * MAD
	scale := 1.4826 * base.MAD
	base.LowerNorm = math.Max(0.0, base.Median-3.0*scale)
	base.UpperNorm = base.Median + 3.0*scale

	return base
}

// IsAnomaly checks if value deviates significantly beyond 3*MAD baseline bounds.
func (b Baseline) IsAnomaly(val float64) bool {
	if b.Samples < 5 || b.MAD == 0 {
		return false
	}
	return val > b.UpperNorm || val < b.LowerNorm
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2.0
}

func formatExhaustionDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", hours, mins)
}
