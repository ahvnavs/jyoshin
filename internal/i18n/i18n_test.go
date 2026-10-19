// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package i18n_test

import (
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/i18n"
)

func TestI18n_BaseEnglish(t *testing.T) {
	i18n.SetLocale("en")
	msg := i18n.T("start_here_lead")
	if !strings.Contains(msg, "read-only server inspector") {
		t.Fatalf("expected English lead message, got %q", msg)
	}
}

func TestI18n_PseudoLocaleExpansion(t *testing.T) {
	i18n.SetLocale("en")
	enVal := i18n.T("start_here_lead")

	i18n.SetLocale("qps-ploc")
	plocVal := i18n.T("start_here_lead")

	t.Logf("English:       %s (len %d)", enVal, len(enVal))
	t.Logf("Pseudo-locale: %s (len %d)", plocVal, len(plocVal))

	// Verify pseudo-locale contains brackets and expansion
	if !strings.HasPrefix(plocVal, "[!!!") || !strings.HasSuffix(plocVal, "!!!]") {
		t.Errorf("pseudo-locale missing delimiter markers: %s", plocVal)
	}

	// Verify length expansion is >= 35%
	if float64(len(plocVal)) < float64(len(enVal))*1.35 {
		t.Errorf("pseudo-locale did not expand length sufficiently: %d vs base %d", len(plocVal), len(enVal))
	}
}

func TestI18n_Formatters(t *testing.T) {
	numStr := i18n.FormatNumber(1234567)
	if numStr != "1,234,567" {
		t.Errorf("unexpected formatted number: %s", numStr)
	}

	tm := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	dtStr := i18n.FormatDate(tm)
	if dtStr != "2026-10-19 12:00:00 UTC" {
		t.Errorf("unexpected formatted date: %s", dtStr)
	}
}

