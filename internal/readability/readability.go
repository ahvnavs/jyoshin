// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package readability provides Flesch-Kincaid Grade Level estimation to ensure
// user-facing summary strings remain accessible and readable below Grade 8.
package readability

import (
	"strings"
	"unicode"
)

// Score calculates the Flesch-Kincaid Grade Level of a text block.
// Formula: 0.39 * (total words / total sentences) + 11.8 * (total syllables / total words) - 15.59
func Score(text string) float64 {
	clean := strings.TrimSpace(text)
	if clean == "" {
		return 0.0
	}

	words := strings.Fields(clean)
	if len(words) == 0 {
		return 0.0
	}

	sentences := countSentences(clean)
	if sentences == 0 {
		sentences = 1
	}

	totalSyllables := 0
	for _, w := range words {
		totalSyllables += countSyllables(w)
	}

	w := float64(len(words))
	s := float64(sentences)
	syll := float64(totalSyllables)

	grade := 0.39*(w/s) + 11.8*(syll/w) - 15.59
	if grade < 0 {
		return 0.0
	}
	return grade
}

func countSentences(text string) int {
	count := 0
	for i, r := range text {
		if r == '.' || r == '!' || r == '?' {
			// Ensure it's not a decimal number like 1.2
			if i > 0 && i < len(text)-1 && unicode.IsDigit(rune(text[i-1])) && unicode.IsDigit(rune(text[i+1])) {
				continue
			}
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}

func countSyllables(word string) int {
	clean := strings.ToLower(strings.TrimFunc(word, func(r rune) bool {
		return !unicode.IsLetter(r)
	}))
	if len(clean) == 0 {
		return 1
	}
	if len(clean) <= 3 {
		return 1
	}

	vowels := "aeiouy"
	count := 0
	lastWasVowel := false

	for _, r := range clean {
		isVowel := strings.ContainsRune(vowels, r)
		if isVowel && !lastWasVowel {
			count++
		}
		lastWasVowel = isVowel
	}

	// Trailing silent 'e'
	if strings.HasSuffix(clean, "e") && !strings.HasSuffix(clean, "le") && count > 1 {
		count--
	}

	if count == 0 {
		return 1
	}
	return count
}
