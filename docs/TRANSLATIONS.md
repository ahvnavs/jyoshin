# Internationalization & Translation Guide

Kazeshini is designed to be accessible to operators and non-technical staff globally.

## Supported Locales
- `en` (English, default)
- `qps-ploc` (Pseudo-localization testing locale with accented characters and +40% string expansion)

## Adding a Translation
1. Copy `web/locales/template.json` to `web/locales/<locale-code>.json` (for example, `es.json` or `ja.json`).
2. Fill in translations for all keys. Keep phrasing simple and human-first.
3. Verify that translations conform to plain language guidelines (Flesch-Kincaid Grade <= 8.0 for summary text).
4. Run tests:
   ```bash
   go test -v ./internal/i18n
   go test -v ./internal/readability
   ```
5. Submit a pull request with your new locale file.

## Text Layout & Expansion
Kazeshini layouts are tested against `qps-ploc` to ensure:
- Button labels and badges do not clip or wrap awkwardly.
- Text boxes handle bidirectional (RTL) text flows gracefully.
- Responsive width down to 320px accommodates expanded words.

