# Security policy

## Scope

PasteGuard is a client-side, pattern-based sanitization helper. It is designed to reduce accidental
exposure when sharing logs, configs, stack traces, and text snippets.

It is **not** a complete data-loss-prevention system, compliance product, malware scanner, secret vault,
or guarantee that every sensitive value will be detected.

## Data handling model

The shipped application:

- processes input in browser memory;
- does not send pasted text to a server or model API;
- does not persist input in local storage, IndexedDB, cookies, or analytics;
- reads imported files through the browser `File` API;
- uses a Content Security Policy restricted to same-origin application resources;
- has no runtime package dependencies.

A fork or third-party deployment can change those properties. Review the deployed source and network
behavior before trusting an unfamiliar hosted instance.

## Threat model

PasteGuard primarily addresses accidental disclosure of recognizable values such as credentials,
personal contact details, internal addresses, local usernames, and invisible control characters.

It does not reliably detect:

- proprietary identifiers without recognizable context;
- secrets encoded, encrypted, compressed, fragmented, or obfuscated beyond built-in rules;
- names, addresses, or free-form personal data requiring language understanding;
- screenshots, PDFs, office documents, images, audio, or binary files;
- secrets introduced after the sanitized text is copied;
- malicious browser extensions, compromised devices, or modified deployments.

## Safe usage

1. Prefer the official source or a deployment you control.
2. Review every replacement and the final output.
3. Do not paste material that policy forbids you from handling in a browser tool.
4. Rotate any credential that may already have been exposed.
5. Use organizational DLP and secret-scanning controls where required.

## Reporting a vulnerability

Before the repository has a dedicated security contact, report vulnerabilities privately to the
repository owner through GitHub's private vulnerability reporting feature. Include reproduction steps,
impact, affected versions, and a minimal synthetic payload.

Do not include real credentials or personal data in a report.
