// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package readability_test

import (
	"testing"

	"github.com/OWNER/kazeshini/internal/glossary"
	"github.com/OWNER/kazeshini/internal/readability"
)

// TestReadability_FleschKincaidUserFacingSummaries asserts that all canonical user-facing
// summary strings score below Flesch-Kincaid Grade 8 (standard general-audience readability).
func TestReadability_FleschKincaidUserFacingSummaries(t *testing.T) {
	terms := glossary.AllTerms()
	if len(terms) == 0 {
		t.Fatal("empty glossary terms catalog")
	}

	maxGradeAllowed := 8.0

	for _, tm := range terms {
		grade := readability.Score(tm.Summary)
		t.Logf("Term %-20s: Flesch-Kincaid Grade %.2f (Summary: %q)", tm.Term, grade, tm.Summary)
		if grade > maxGradeAllowed {
			t.Errorf("READABILITY BREACH: Term %q summary exceeds grade %.1f: got %.2f\nText: %s",
				tm.Term, maxGradeAllowed, grade, tm.Summary)
		}
	}
}
