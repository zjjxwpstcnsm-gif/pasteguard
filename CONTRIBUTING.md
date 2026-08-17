# Contributing to PasteGuard

Thank you for helping make text sharing safer and easier.

## Before opening an issue

For detector bugs, provide the smallest synthetic example that demonstrates the behavior. Never put a
real credential, production token, private key, customer record, or confidential log in an issue.

Good example:

```text
Input: api_key = "sk-demo-abcdefghijklmnop"
Expected: api_key = "<SECRET_1>"
Actual: unchanged
```

## Local development

```bash
npm install
npm run dev
```

Before submitting a pull request:

```bash
npm run check
```

## Adding or changing a detector

A detector change should include:

1. A narrow problem statement.
2. At least one positive test.
3. At least one nearby negative test.
4. A documented severity and confidence level.
5. A reason for its priority when overlap with another rule is possible.

Rules live in `src/engine/rules.ts`. Keep detectors deterministic and synchronous. Avoid network calls,
remote models, browser storage, and large dependencies.

## Rule quality guidelines

Prefer contextual evidence over broad string matching. For example, a value following
`Authorization: Bearer` is more reliable than an arbitrary long alphanumeric string.

Use validation where possible:

- parse IP octets instead of matching only their shape;
- use the Luhn checksum for payment cards;
- require explicit secret-related keys for generic assignments;
- reject matches embedded inside larger identifiers.

A detector that produces frequent false positives should be disabled in the Balanced preset or omitted
until it can be narrowed.

## Pull requests

Keep pull requests small. Explain user-visible behavior, test coverage, and any false-positive trade-off.
Do not combine unrelated UI redesigns and detector changes in one pull request.

## Security reports

Do not file exploitable security problems publicly. Follow [SECURITY.md](SECURITY.md).
