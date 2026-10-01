# Changelog

All notable changes to PasteGuard will be documented in this file.

## Unreleased

### Fixed

- Match escaped and namespaced secret assignments, JSON/curl/indented authorization and cookie headers,
  and signed or encoded URL parameter names while preserving benign keys and surrounding syntax.
- Detect secrets assembled by enabled invisible-character cleanup and preserve original source locations.
- Redact complete enclosing secrets instead of leaking the remainder after an inner match wins.
- Recognize contextual compact phone values, adjacent formatted phones, terminal home paths,
  quoted usernames, and JSON-escaped Windows paths without broadening generic numeric-ID matching.
- Preserve existing placeholders, prevent numbering collisions, and refresh the hosted service-worker cache.
- Add a synthetic missed-case/nearby-negative corpus and large-log regressions; rebuild both offline files.

### Added

- A separately controllable Basic/Token authorization-credential rule and encrypted-PEM coverage.

## 0.1.0 - 2026-08-17

### Added

- Local-first browser interface for reviewing and sanitizing text.
- Nineteen deterministic detection rules across secrets, personal data, network details, device paths, identifiers, and text hygiene.
- Stable placeholders and overlap-aware replacement behavior.
- Balanced, Secrets only, Public issue, and Strict protection profiles.
- Standalone `portable/pasteguard-local.html` edition that opens without npm or a local server.
- Root-level `sharesafe-local.html` compatibility copy with identical PasteGuard content.
- GitHub Pages deployment workflow, continuous integration, security policy, contribution guide, and detector issue templates.
