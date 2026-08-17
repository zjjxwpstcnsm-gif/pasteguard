# Roadmap

## 0.1 — Browser MVP

- [x] Local-only text processing
- [x] Stable placeholders
- [x] Explainable findings with source locations
- [x] Four protection presets
- [x] Text-file import, copy, and download
- [x] PWA shell and offline asset cache
- [x] Strict TypeScript and automated detector tests
- [x] GitHub Pages workflow

## 0.2 — Trust and accuracy

- [ ] Expand positive and negative detector fixtures
- [ ] Add per-finding accept/reject controls
- [ ] Highlight source and output ranges
- [ ] Add a session-only custom dictionary
- [ ] Add a detector performance benchmark
- [ ] Publish a documented browser support matrix

## 0.3 — Reusable core

- [ ] Publish the sanitizer engine as a separate npm package
- [ ] Add a zero-configuration CLI for stdin and files
- [ ] Support machine-readable JSON findings
- [ ] Add rule plugins without executing untrusted code

## Later, only with demand

- [ ] Browser extension
- [ ] VS Code extension
- [ ] Structured JSON/YAML-aware redaction
- [ ] Additional languages

## Explicitly out of scope for now

Accounts, cloud storage, team dashboards, remote AI inference, PDF/OCR processing, reversible vaults,
and enterprise policy management. These would change the project's privacy and maintenance model.
