# Detection rules

PasteGuard rules are deterministic functions that return text ranges. The sanitizer resolves overlaps by
rule priority, then replaces selected ranges from left to right.

## Placeholder behavior

Each detected value has a placeholder kind, such as `EMAIL`, `IP_ADDRESS`, or `SECRET`. The same
canonical value receives the same numbered placeholder during one sanitization run:

```text
maya@example.com → <EMAIL_1>
lee@example.com  → <EMAIL_2>
maya@example.com → <EMAIL_1>
```

Placeholder mappings are kept only in memory and are discarded with the page state.

## Built-in rules

| Rule ID | Category | Default | Severity | Notes |
|---|---|---:|---|---|
| `private-key` | Secrets | Yes | Critical | PEM private key blocks |
| `cookie-header` | Secrets | Yes | Critical | Entire Cookie or Set-Cookie value |
| `bearer-token` | Secrets | Yes | Critical | Contextual Authorization header value |
| `database-password` | Secrets | Yes | Critical | Password inside common connection URLs |
| `url-secret` | Secrets | Yes | Critical | Sensitive query-parameter values |
| `secret-assignment` | Secrets | Yes | Critical | Password, key, token, and secret assignments |
| `known-access-token` | Secrets | Yes | Critical | Selected high-signal token prefixes |
| `jwt` | Secrets | Yes | High | Three-segment JWT-shaped values |
| `payment-card` | Personal | Yes | Critical | 13–19 digits plus Luhn validation |
| `email` | Personal | Yes | High | Common mailbox formats |
| `phone` | Personal | Yes | Medium | Phone-shaped values; medium confidence |
| `ip-address` | Network | Yes | Medium | IPv4 with octet validation |
| `mac-address` | Network | Yes | Medium | Colon- or dash-separated MAC addresses |
| `local-user` | Device | Yes | Medium | Username portion of common home paths |
| `identifier-assignment` | Identifiers | No | Medium | Contextual generic IDs; medium confidence |
| `uuid` | Identifiers | No | Low | Standard UUIDs |
| `bidi-control` | Hygiene | Yes | High | Invisible bidirectional controls, removed |
| `zero-width` | Hygiene | Yes | Medium | Zero-width characters, removed |
| `ansi-sequence` | Hygiene | Yes | Low | Terminal escape sequences, removed |

## Overlap policy

Contextual rules intentionally outrank generic rules. For example, a JWT inside an Authorization header
becomes `<BEARER_TOKEN_1>`, not `<JWT_1>`. A Luhn-valid payment card outranks a phone-shaped match.

When changing priorities, add a regression test that demonstrates the intended winner.

## Adding a rule

A rule implements the `Rule` interface in `src/engine/types.ts` and is registered in
`src/engine/rules.ts`. New default rules should have a low false-positive rate. Less certain rules belong
in Strict mode until enough evidence supports enabling them by default.
