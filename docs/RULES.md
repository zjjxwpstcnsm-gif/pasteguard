# Detection rules

PasteGuard rules are deterministic functions that return text ranges. Before matching, enabled hygiene rules remove known invisible controls and ANSI escapes from a scanning
copy. Findings still refer to the original input ranges and line/column positions. The sanitizer resolves
overlapping sensitive ranges, then replaces selected ranges from left to right.

## Placeholder behavior

Each detected value has a placeholder kind, such as `EMAIL`, `IP_ADDRESS`, or `SECRET`. The same
canonical value receives the same numbered placeholder during one sanitization run:

```text
maya@example.com → <EMAIL_1>
lee@example.com  → <EMAIL_2>
maya@example.com → <EMAIL_1>
```

Placeholder mappings are kept only in memory and are discarded with the page state. Existing numbered
placeholders are preserved and reserved, so newly found values cannot collide with them.

## Built-in rules

| Rule ID | Category | Default | Severity | Notes |
|---|---|---:|---|---|
| `private-key` | Secrets | Yes | Critical | PEM private key blocks, including encrypted keys |
| `cookie-header` | Secrets | Yes | Critical | Entire Cookie or Set-Cookie value |
| `bearer-token` | Secrets | Yes | Critical | Bearer credentials in plain, JSON, or curl headers |
| `authorization-credential` | Secrets | Yes | Critical | Basic/Token credentials in Authorization or Proxy-Authorization headers |
| `database-password` | Secrets | Yes | Critical | Password inside common connection URLs |
| `url-secret` | Secrets | Yes | Critical | Sensitive query-parameter values |
| `secret-assignment` | Secrets | Yes | Critical | Bounded secret keys, including camelCase and namespaced environment keys; escaped quoted values |
| `known-access-token` | Secrets | Yes | Critical | Selected high-signal token prefixes |
| `jwt` | Secrets | Yes | High | Three-segment JWT-shaped values |
| `payment-card` | Personal | Yes | Critical | 13–19 digits plus Luhn validation |
| `email` | Personal | Yes | High | Common mailbox formats |
| `phone` | Personal | Yes | Medium | Conservative formatted numbers or explicit phone labels; medium confidence |
| `ip-address` | Network | Yes | Medium | IPv4 with octet validation |
| `mac-address` | Network | Yes | Medium | Colon- or dash-separated MAC addresses |
| `local-user` | Device | Yes | Medium | Terminal/quoted home paths and JSON-escaped Windows paths |
| `identifier-assignment` | Identifiers | No | Medium | Contextual generic IDs; medium confidence |
| `uuid` | Identifiers | No | Low | Standard UUIDs |
| `bidi-control` | Hygiene | Yes | High | Invisible bidirectional controls, removed |
| `zero-width` | Hygiene | Yes | Medium | Zero-width characters, removed |
| `ansi-sequence` | Hygiene | Yes | Low | Terminal escape sequences, removed |

## Overlap policy

A larger enclosing secret takes precedence over a contained match, even if the contained rule normally
has higher priority. For example, `password="prefix?token=inner"` redacts the complete assigned value.
For equal ranges and other overlaps, contextual rules intentionally outrank generic rules. For example, a JWT inside an Authorization header
becomes `<BEARER_TOKEN_1>`, not `<JWT_1>`. A Luhn-valid payment card outranks a phone-shaped match.

Hygiene characters inside a replaced value are covered by that replacement instead of producing nested
findings. Disabled hygiene rules do not normalize the scanning copy.

When changing priorities, add a regression test that demonstrates the intended winner.

## Context and false-positive limits

- Assignment matching uses complete keys. `dbPassword`, `AWS_SECRET_ACCESS_KEY`, `refresh_token`,
  and `session_token` are recognized; `notpassword`, `password_hint`, and `token_count` are not.
  Single/double/backtick-quoted values support escaped quotes; YAML doubled single quotes are recognized.
  An empty assignment cannot consume the next line. Literal multiline scalars and object/array-valued secret fields are not parsed as structured values.
- Authorization and Cookie headers support indented text, quoted JSON keys/values, and common curl
  header strings. Basic credentials are replaced directly without decoding or sending them anywhere.
  Only explicit Bearer, Basic, and Token authorization schemes are recognized.
- URL parameters require an entire sensitive name and `=`. Percent-encoded parameter names and HTML
  `&amp;` separators are supported, as are AWS/Google signed-URL signatures and credentials. Parameter
  values remain encoded; arbitrary nested/encoded payloads are not recursively decoded.
- Compact phone numbers need an adjacent phone/mobile/tel or supported Chinese telephone label.
  Unlabelled numbers use conservative international/North American shapes. This is a medium-confidence
  heuristic, not complete global telephone validation. Dates, IPs, long digit runs, identifiers, and
  Luhn-valid cards are rejected by the phone detector.
- Home-path matching covers `/Users/`, `/home/`, and Windows `Users` with real or JSON-escaped
  backslashes. Quoted usernames may contain spaces. Website URL paths and existing placeholders are
  left alone. POSIX usernames retain case; Windows usernames use case-insensitive canonical values.

Tests in `tests/matching-corpus.mjs` pair missed synthetic cases with nearby non-sensitive examples.
Other tests cover original source locations, enabled-rule behavior, placeholder stability, and a
2,000-line obfuscated log. Passing this corpus is a regression check, not a general recall guarantee.

## Adding a rule

A rule implements the `Rule` interface in `src/engine/types.ts` and is registered in
`src/engine/rules.ts`. New default rules should have a low false-positive rate. Less certain rules belong
in Strict mode until enough evidence supports enabling them by default.
