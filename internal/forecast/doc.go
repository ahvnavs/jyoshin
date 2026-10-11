// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package forecast implements linear regression and rolling baseline forecasting
// for server resources.
//
// Non-negotiable principles:
// 1. NO AI/LLM/ML anywhere. Deterministic, explainable logic only (rules + statistics).
// Statistics only: linear regression forecasts, rolling baselines, snapshot diffs.
package forecast
