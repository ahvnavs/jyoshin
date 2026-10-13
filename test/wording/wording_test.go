package wording_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBannedTermsFailsBuild ensures user-facing UI, documentation, and CLI files
// contain zero occurrences of banned terms: DevOps, DevSecOps, Cloud Platform,
// Chaos, Calm, Briefing, Doctor, Symptom, or playful jargon.
func TestBannedTermsFailsBuild(t *testing.T) {
	bannedTerms := []string{
		`\bDevOps\b`,
		`\bDevSecOps\b`,
		`\bCloud Platform\b`,
		`\bChaos\b`,
		`\bCalm\b`,
		`\bBriefing\b`,
		`\bDoctor\b`,
		`\bSymptom\b`,
	}

	compiled := make([]*regexp.Regexp, len(bannedTerms))
	for i, pattern := range bannedTerms {
		compiled[i] = regexp.MustCompile("(?i)" + pattern)
	}

	// Directories containing user-facing copy to check:
	// - web/ (HTML, JS, CSS)
	// - internal/contract/render.go
	// - data/wording.yaml
	// Note: We scan web/ thoroughly, plus contract rendering.
	scanTargets := []string{
		"../../web/index.html",
		"../../web/css/style.css",
		"../../data/wording.yaml",
		"../../docs/GLOSSARY.md",
	}

	for _, target := range scanTargets {
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("failed reading target %s: %v", target, err)
		}

		lines := bytes.Split(data, []byte("\n"))
		for lineNum, line := range lines {
			lineStr := string(line)
			// Skip markdown explanation in GLOSSARY of what terms were replaced/banned
			if strings.Contains(target, "GLOSSARY.md") && (strings.Contains(lineStr, "Banned Term") || strings.Contains(lineStr, "Deprecated") || strings.Contains(lineStr, "Replaced by")) {
				continue
			}
			for _, re := range compiled {
				if loc := re.FindStringIndex(lineStr); loc != nil {
					match := lineStr[loc[0]:loc[1]]
					t.Errorf("Banned term %q found in %s:%d: %s", match, target, lineNum+1, strings.TrimSpace(lineStr))
				}
			}
		}
	}

	// Also check web/js/app.js excluding backward-compatibility fallback keys (like chaos_index / chaos_contributors)
	appJSData, err := os.ReadFile("../../web/js/app.js")
	if err != nil {
		t.Fatalf("failed reading web/js/app.js: %v", err)
	}
	for lineNum, line := range bytes.Split(appJSData, []byte("\n")) {
		lineStr := string(line)
		// Ignore legacy compatibility fallback references in JS
		if strings.Contains(lineStr, "chaos_index") || strings.Contains(lineStr, "chaos_contributors") {
			continue
		}
		for _, re := range compiled {
			if loc := re.FindStringIndex(lineStr); loc != nil {
				match := lineStr[loc[0]:loc[1]]
				t.Errorf("Banned term %q found in web/js/app.js:%d: %s", match, lineNum+1, strings.TrimSpace(lineStr))
			}
		}
	}

	// Walk web directory to ensure no rogue HTML files contain banned terms
	err = filepath.WalkDir("../../web", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".html" {
			content, _ := os.ReadFile(path)
			for _, re := range compiled {
				if re.Match(content) {
					t.Errorf("Banned term matched in HTML file %s", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed walking web dir: %v", err)
	}
}

