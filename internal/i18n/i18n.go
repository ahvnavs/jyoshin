// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package i18n provides localized message formatting, locale-aware date/number presentation,
// and pseudo-localization generation for layout stress-testing.
package i18n

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	mu       sync.RWMutex
	current  = "en"
	messages = make(map[string]map[string]string)
)

func init() {
	// Base English dictionary
	messages["en"] = map[string]string{
		"start_here_lead":    "Kazeshini is a read-only server inspector.",
		"start_here_safety":  "It only inspects system status and makes zero modifications to this host.",
		"start_here_next":    "Review the findings below or click 'What should I do now?' for guidance.",
		"what_to_do_title":   "What should I do now?",
		"top_recommendation": "Primary Recommended Action",
		"copy_command":       "Copy",
		"ask_technical":      "Ask someone technical",
		"technical_summary":  "One-Page Technical Summary",
		"close":              "Close",
		"print":              "Print / Save PDF",
		"risk_score":         "Risk Score",
		"healthy":            "Healthy",
		"degraded":           "Degraded",
		"critical":           "Critical",
		"visibility":         "Visibility",
		"unmanaged_software": "Unmanaged software",
	}

	// Pseudo-locale: QPS-PLOC (accented glyphs + ~40% expansion to stress-test UI/CLI wrappers)
	messages["qps-ploc"] = generatePseudoLocale(messages["en"])
}

// Pseudo-localization mapping (converts ASCII to visually accented equivalents and expands length)
func generatePseudoLocale(base map[string]string) map[string]string {
	ploc := make(map[string]string, len(base))
	charMap := map[rune]rune{
		'a': 'á', 'b': 'ḅ', 'c': 'ç', 'd': 'ḍ', 'e': 'é', 'f': 'ƒ', 'g': 'ĝ',
		'h': 'ĥ', 'i': 'í', 'j': 'ĵ', 'k': 'ḳ', 'l': 'ŀ', 'm': 'ḿ', 'n': 'ñ',
		'o': 'ō', 'p': 'ṗ', 'q': 'ʠ', 'r': 'ř', 's': 'š', 't': 'ţ', 'u': 'ú',
		'v': 'ṽ', 'w': 'ŵ', 'x': 'ẋ', 'y': 'ý', 'z': 'ž',
		'A': 'Á', 'B': 'Ḅ', 'C': 'Ç', 'D': 'Ḍ', 'E': 'É', 'F': 'Ƒ', 'G': 'Ĝ',
		'H': 'Ĥ', 'I': 'Í', 'J': 'Ĵ', 'K': 'Ḳ', 'L': 'Ł', 'M': 'Ḿ', 'N': 'Ñ',
		'O': 'Ō', 'P': 'Ṗ', 'Q': 'Ǫ', 'R': 'Ř', 'S': 'Š', 'T': 'Ţ', 'U': 'Ú',
		'V': 'Ṽ', 'W': 'Ŵ', 'X': 'Ẋ', 'Y': 'Ý', 'Z': 'Ž',
	}

	for k, v := range base {
		var sb strings.Builder
		sb.WriteString("[!!! ")
		for _, r := range v {
			if sub, ok := charMap[r]; ok {
				sb.WriteRune(sub)
			} else {
				sb.WriteRune(r)
			}
		}
		// Expand string by approximately 40% with pseudo-expansion tail
		padLen := (len(v) * 4) / 10
		if padLen > 0 {
			sb.WriteString(" ")
			for i := 0; i < padLen; i++ {
				sb.WriteString("~")
			}
		}
		sb.WriteString(" !!!]")
		ploc[k] = sb.String()
	}
	return ploc
}

// SetLocale changes the active locale.
func SetLocale(loc string) {
	mu.Lock()
	defer mu.Unlock()
	current = strings.ToLower(strings.TrimSpace(loc))
}

// GetLocale returns the current active locale.
func GetLocale() string {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// T translates a key in the active locale, falling back to English, then the key itself.
func T(key string) string {
	mu.RLock()
	defer mu.RUnlock()
	if dict, ok := messages[current]; ok {
		if val, exists := dict[key]; exists {
			return val
		}
	}
	if dict, ok := messages["en"]; ok {
		if val, exists := dict[key]; exists {
			return val
		}
	}
	return key
}

// FormatNumber formats an integer with locale-appropriate grouping.
func FormatNumber(n int64) string {
	// Standard comma-separated grouping
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var res []string
	for len(s) > 3 {
		res = append([]string{s[len(s)-3:]}, res...)
		s = s[:len(s)-3]
	}
	if len(s) > 0 {
		res = append([]string{s}, res...)
	}
	return strings.Join(res, ",")
}

// FormatDate returns an ISO 8601/locale-clean UTC date string.
func FormatDate(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// LoadLocaleJSON loads a translation catalog from JSON bytes.
func LoadLocaleJSON(locale string, data []byte) error {
	var dict map[string]string
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	messages[strings.ToLower(strings.TrimSpace(locale))] = dict
	return nil
}
