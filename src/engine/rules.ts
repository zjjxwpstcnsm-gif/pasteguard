import { detectNamedGroup, detectWholeMatch, mergeDetections } from './detectors.js';
import { passesLuhn } from './luhn.js';
import { detectLocalUsernames, detectPhoneNumbers } from './personal.js';
import { assignmentDetection, assignmentValues, isRedactedPlaceholder, normalizedKey } from './assignments.js';
import type { Detection, Rule } from './types.js';

function detectPrivateKeys(text: string): Detection[] {
  return detectWholeMatch(
    text,
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    'PRIVATE_KEY',
  );
}

function detectAuthorization(text: string, bearer: boolean): Detection[] {
  const detections: Detection[] = [];
  for (const header of assignmentValues(text, (key) => /^(?:proxy-)?authorization$/i.test(key), 'authorization')) {
    const match = /^(Bearer|Basic|Token)[\t ]+([A-Za-z0-9._~+/=-]+)/i.exec(header.value);
    if (!match || (match[1]?.toLowerCase() === 'bearer') !== bearer) {
      continue;
    }
    const credential = match[2];
    if (!credential) {
      continue;
    }
    const start = header.start + match[0].length - credential.length;
    detections.push({ start, end: start + credential.length, value: credential,
      kind: bearer ? 'BEARER_TOKEN' : 'AUTH_CREDENTIAL' });
  }
  return detections;
}

function detectBearerTokens(text: string): Detection[] {
  return detectAuthorization(text, true);
}

function detectCookieHeaders(text: string): Detection[] {
  return assignmentValues(text, (key) => /^(?:set-)?cookie$/i.test(key), 'cookie')
    .map((value) => assignmentDetection(value, 'COOKIE'));
}

function detectJwtTokens(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /\b(?<value>eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})\b/g,
    { kind: 'JWT' },
  );
}

function detectKnownAccessTokens(text: string): Detection[] {
  return mergeDetections(
    detectNamedGroup(text, /\b(?<value>github_pat_[A-Za-z0-9_]{20,255})\b/g, {
      kind: 'ACCESS_TOKEN',
    }),
    detectNamedGroup(text, /\b(?<value>gh[pousr]_[A-Za-z0-9]{20,255})\b/g, {
      kind: 'ACCESS_TOKEN',
    }),
    detectNamedGroup(text, /\b(?<value>(?:AKIA|ASIA)[A-Z0-9]{16})\b/g, {
      kind: 'CLOUD_ACCESS_KEY',
    }),
    detectNamedGroup(text, /\b(?<value>AIza[0-9A-Za-z_-]{30,})\b/g, {
      kind: 'API_KEY',
    }),
    detectNamedGroup(text, /\b(?<value>xox[baprs]-[0-9A-Za-z-]{12,})\b/g, {
      kind: 'ACCESS_TOKEN',
    }),
    detectNamedGroup(text, /\b(?<value>sk-[A-Za-z0-9_-]{16,})\b/g, {
      kind: 'API_KEY',
    }),
  );
}

function detectSecretAssignments(text: string): Detection[] {
  return assignmentValues(text, (key) =>
    /(?:^|_)(?:api_?key|secret(?:_?(?:key|access_?key))?|client_?secret|(?:access|auth|refresh|id|session)_?token|token|password|passwd|pwd|private_?key)$/.test(normalizedKey(key)),
  )
    .filter(({ value }) => !/^(?:null|none|undefined|false|true|changeme|example)$/i.test(value))
    .map((value) => assignmentDetection(value, 'SECRET'));
}

function detectSensitiveUrlParameters(text: string): Detection[] {
  const detections: Detection[] = [];
  // Require a complete parameter name and '='. Never match token_count or tokenizer.
  const parameters = /[?&](?:amp;)?([^=&#\s"'<>]+)=(?<value>[^&#\s"'<>]*)/gd;
  for (const match of text.matchAll(parameters)) {
    let key: string;
    try {
      key = decodeURIComponent(match[1] ?? '').toLowerCase();
    } catch {
      continue;
    }
    if (!/^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|password|passwd|secret|signature|sig|auth|client[_-]?secret|x-amz-(?:signature|credential|security-token)|x-goog-(?:signature|credential))$/.test(key)) {
      continue;
    }
    const value = match.groups?.value;
    const range = match.indices?.groups?.value;
    if (value && range && !isRedactedPlaceholder(value)) {
      detections.push({ start: range[0], end: range[1], value, kind: 'URL_SECRET' });
    }
  }
  return detections;
}

function detectDatabasePasswords(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps):\/\/[^:\s/@]*:(?<value>[^\s/"\'<>]+)@/gi,
    { kind: 'DATABASE_PASSWORD' },
  );
}

function detectEmails(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])(?<value>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)/gi,
    { kind: 'EMAIL' },
  ).map((detection) => {
    // '=' is legal in mailbox local parts, but preserve common log assignment keys.
    const prefix = /^(?:(?:contact[_-]?)?email(?:[_-]?address)?|mail|user(?:name)?|owner|from|to|cc|bcc)=/i.exec(detection.value)?.[0] ?? '';
    const value = detection.value.slice(prefix.length);
    return { ...detection, start: detection.start + prefix.length, value, canonicalValue: value.toLowerCase() };
  });
}

function detectPaymentCards(text: string): Detection[] {
  const regex = /\b(?:\d[ -]?){12,18}\d\b/g;
  const detections: Detection[] = [];

  for (const match of text.matchAll(regex)) {
    const value = match[0];
    const start = match.index;
    if (start === undefined || !passesLuhn(value)) {
      continue;
    }

    detections.push({
      start,
      end: start + value.length,
      value,
      canonicalValue: value.replace(/\D/g, ''),
      kind: 'PAYMENT_CARD',
    });
  }

  return detections;
}

function detectIpv4Addresses(text: string): Detection[] {
  const regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const detections: Detection[] = [];

  for (const match of text.matchAll(regex)) {
    const value = match[0];
    const start = match.index;
    if (start === undefined) {
      continue;
    }

    const valid = value.split('.').every((part) => {
      if (part.length > 1 && part.startsWith('0')) {
        return false;
      }
      const number = Number(part);
      return Number.isInteger(number) && number >= 0 && number <= 255;
    });

    if (valid) {
      detections.push({
        start,
        end: start + value.length,
        value,
        kind: 'IP_ADDRESS',
      });
    }
  }

  return detections;
}

function detectMacAddresses(text: string): Detection[] {
  return detectNamedGroup(text, /\b(?<value>(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2})\b/gi, {
    kind: 'MAC_ADDRESS',
    canonicalize: (value) => value.toLowerCase().replace(/-/g, ':'),
  });
}

function detectUuids(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /\b(?<value>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b/gi,
    {
      kind: 'UUID',
      canonicalize: (value) => value.toLowerCase(),
    },
  );
}

function detectIdentifierAssignments(text: string): Detection[] {
  return assignmentValues(text, (key) =>
    /^(?:user|account|customer|session|request|trace|device)_?id$/.test(normalizedKey(key)),
  ).map((value) => ({ ...assignmentDetection(value, 'IDENTIFIER'), confidence: 'medium' as const }));
}

function detectAnsiSequences(text: string): Detection[] {
  return detectWholeMatch(text, /\u001B(?:\[[0-?]*[ -/]*[@-~]|[@-_])/g, 'ANSI_SEQUENCE', '');
}

function detectZeroWidthCharacters(text: string): Detection[] {
  return detectWholeMatch(text, /[\u200B-\u200D\u2060\uFEFF]/g, 'ZERO_WIDTH_CHARACTER', '');
}

function detectBidirectionalControls(text: string): Detection[] {
  return detectWholeMatch(
    text,
    /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g,
    'BIDI_CONTROL',
    '',
  );
}

export const RULES: Rule[] = [
  {
    id: 'private-key',
    label: 'Private keys',
    description: 'PEM-encoded private key blocks.',
    category: 'secrets',
    severity: 'critical',
    priority: 120,
    enabledByDefault: true,
    detect: detectPrivateKeys,
  },
  {
    id: 'cookie-header',
    label: 'Cookie headers',
    description: 'Cookie and Set-Cookie header values.',
    category: 'secrets',
    severity: 'critical',
    priority: 110,
    enabledByDefault: true,
    detect: detectCookieHeaders,
  },
  {
    id: 'bearer-token',
    label: 'Bearer tokens',
    description: 'Authorization header bearer credentials.',
    category: 'secrets',
    severity: 'critical',
    priority: 105,
    enabledByDefault: true,
    detect: detectBearerTokens,
  },
  {
    id: 'authorization-credential',
    label: 'Authorization credentials',
    description: 'Basic and Token credentials in Authorization and Proxy-Authorization headers.',
    category: 'secrets',
    severity: 'critical',
    priority: 104,
    enabledByDefault: true,
    detect: (text) => detectAuthorization(text, false),
  },
  {
    id: 'database-password',
    label: 'Database passwords',
    description: 'Passwords embedded in common database connection URLs.',
    category: 'secrets',
    severity: 'critical',
    priority: 100,
    enabledByDefault: true,
    detect: detectDatabasePasswords,
  },
  {
    id: 'url-secret',
    label: 'Sensitive URL parameters',
    description: 'Tokens, keys, passwords, and signatures in URL query strings.',
    category: 'secrets',
    severity: 'critical',
    priority: 96,
    enabledByDefault: true,
    detect: detectSensitiveUrlParameters,
  },
  {
    id: 'secret-assignment',
    label: 'Assigned secrets',
    description: 'Password, API key, token, and secret values in configs or logs.',
    category: 'secrets',
    severity: 'critical',
    priority: 92,
    enabledByDefault: true,
    detect: detectSecretAssignments,
  },
  {
    id: 'known-access-token',
    label: 'Known token formats',
    description: 'Common API and access-token prefixes.',
    category: 'secrets',
    severity: 'critical',
    priority: 88,
    enabledByDefault: true,
    detect: detectKnownAccessTokens,
  },
  {
    id: 'jwt',
    label: 'JSON Web Tokens',
    description: 'JWT-like three-segment tokens.',
    category: 'secrets',
    severity: 'high',
    priority: 84,
    enabledByDefault: true,
    detect: detectJwtTokens,
  },
  {
    id: 'payment-card',
    label: 'Payment card numbers',
    description: '13–19 digit numbers that pass the Luhn checksum.',
    category: 'personal',
    severity: 'critical',
    priority: 76,
    enabledByDefault: true,
    detect: detectPaymentCards,
  },
  {
    id: 'email',
    label: 'Email addresses',
    description: 'Common email address formats.',
    category: 'personal',
    severity: 'high',
    priority: 65,
    enabledByDefault: true,
    detect: detectEmails,
  },
  {
    id: 'phone',
    label: 'Phone numbers',
    description: 'Phone-shaped international and local number patterns.',
    category: 'personal',
    severity: 'medium',
    priority: 48,
    enabledByDefault: true,
    detect: detectPhoneNumbers,
  },
  {
    id: 'ip-address',
    label: 'IPv4 addresses',
    description: 'Valid IPv4 addresses, including private network addresses.',
    category: 'network',
    severity: 'medium',
    priority: 58,
    enabledByDefault: true,
    detect: detectIpv4Addresses,
  },
  {
    id: 'mac-address',
    label: 'MAC addresses',
    description: 'Colon- or dash-separated hardware addresses.',
    category: 'network',
    severity: 'medium',
    priority: 54,
    enabledByDefault: true,
    detect: detectMacAddresses,
  },
  {
    id: 'local-user',
    label: 'Local usernames',
    description: 'Usernames exposed by macOS, Linux, and Windows home paths.',
    category: 'device',
    severity: 'medium',
    priority: 52,
    enabledByDefault: true,
    detect: detectLocalUsernames,
  },
  {
    id: 'identifier-assignment',
    label: 'Assigned identifiers',
    description: 'User, account, session, request, trace, and device IDs.',
    category: 'identifiers',
    severity: 'medium',
    priority: 44,
    enabledByDefault: false,
    detect: detectIdentifierAssignments,
  },
  {
    id: 'uuid',
    label: 'UUIDs',
    description: 'Standard UUID values that may identify users, devices, or requests.',
    category: 'identifiers',
    severity: 'low',
    priority: 42,
    enabledByDefault: false,
    detect: detectUuids,
  },
  {
    id: 'bidi-control',
    label: 'Bidirectional controls',
    description: 'Invisible direction-control characters that can disguise text.',
    category: 'hygiene',
    severity: 'high',
    priority: 40,
    enabledByDefault: true,
    detect: detectBidirectionalControls,
  },
  {
    id: 'zero-width',
    label: 'Zero-width characters',
    description: 'Invisible spacing characters that can hide inside copied text.',
    category: 'hygiene',
    severity: 'medium',
    priority: 36,
    enabledByDefault: true,
    detect: detectZeroWidthCharacters,
  },
  {
    id: 'ansi-sequence',
    label: 'Terminal color codes',
    description: 'ANSI escape sequences copied from terminal output.',
    category: 'hygiene',
    severity: 'low',
    priority: 32,
    enabledByDefault: true,
    detect: detectAnsiSequences,
  },
];

export const RULE_BY_ID = new Map(RULES.map((rule) => [rule.id, rule]));
