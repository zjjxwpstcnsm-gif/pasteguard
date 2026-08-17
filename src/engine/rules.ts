import { detectNamedGroup, detectWholeMatch, mergeDetections } from './detectors.js';
import { passesLuhn } from './luhn.js';
import type { Detection, Rule } from './types.js';

function stripMatchingQuotes(detection: Detection): Detection | null {
  const first = detection.value.at(0);
  const last = detection.value.at(-1);
  if ((first === '"' || first === "'") && last === first) {
    if (detection.value.length <= 2) {
      return null;
    }
    return {
      ...detection,
      start: detection.start + 1,
      end: detection.end - 1,
      value: detection.value.slice(1, -1),
      canonicalValue: detection.value.slice(1, -1),
    };
  }
  return detection;
}

function detectPrivateKeys(text: string): Detection[] {
  return detectWholeMatch(
    text,
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    'PRIVATE_KEY',
  );
}

function detectBearerTokens(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /\bAuthorization\s*:\s*Bearer\s+(?<value>[A-Za-z0-9._~+/=-]{8,})/gi,
    { kind: 'BEARER_TOKEN' },
  );
}

function detectCookieHeaders(text: string): Detection[] {
  return detectNamedGroup(text, /^(?:Cookie|Set-Cookie)\s*:\s*(?<value>[^\r\n]+)/gim, {
    kind: 'COOKIE',
  });
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
  const detections = detectNamedGroup(
    text,
    /["']?(?:api[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)["']?\s*(?:=|:)\s*(?<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;#}\]]+)/gi,
    { kind: 'SECRET' },
  );

  return detections
    .map(stripMatchingQuotes)
    .filter((detection): detection is Detection => detection !== null)
    .filter((detection) => !/^(?:null|none|undefined|false|true|changeme|example)$/i.test(detection.value));
}

function detectSensitiveUrlParameters(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /[?&](?:access[_-]?token|token|api[_-]?key|password|passwd|secret|signature|sig|auth)=?(?<value>[^&#\s]*)/gi,
    { kind: 'URL_SECRET' },
  ).filter((detection) => detection.value.length > 0);
}

function detectDatabasePasswords(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps):\/\/[^:\s/@]+:(?<value>[^@\s/]+)@/gi,
    { kind: 'DATABASE_PASSWORD' },
  );
}

function detectEmails(text: string): Detection[] {
  return detectNamedGroup(
    text,
    /(?<value>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)/gi,
    {
      kind: 'EMAIL',
      canonicalize: (value) => value.toLowerCase(),
    },
  );
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

function detectPhoneNumbers(text: string): Detection[] {
  const regex = /(?:\+\d{1,3}[\s().-]*)?(?:\(?\d{2,4}\)?[\s.-]*){2,5}\d{2,4}/g;
  const detections: Detection[] = [];

  for (const match of text.matchAll(regex)) {
    const raw = match[0].trim();
    const originalStart = match.index;
    if (originalStart === undefined || raw.length === 0) {
      continue;
    }

    const leadingTrim = match[0].length - match[0].trimStart().length;
    const start = originalStart + leadingTrim;
    const end = start + raw.length;
    const before = text[start - 1] ?? '';
    const after = text[end] ?? '';
    const touchesIdentifier = /[A-Za-z0-9]/.test(before) || /[A-Za-z0-9]/.test(after);
    const digits = raw.replace(/\D/g, '');
    const hasPhoneShape = raw.startsWith('+') || /[()]/.test(raw) || (raw.match(/[ .-]/g)?.length ?? 0) >= 2;
    const looksLikeDate = /^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$/.test(raw);
    const looksLikeIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw);

    if (
      digits.length < 7 ||
      digits.length > 15 ||
      !hasPhoneShape ||
      touchesIdentifier ||
      looksLikeDate ||
      looksLikeIp ||
      passesLuhn(raw)
    ) {
      continue;
    }

    detections.push({
      start,
      end,
      value: raw,
      canonicalValue: digits,
      kind: 'PHONE',
      confidence: 'medium',
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

function detectLocalUsernames(text: string): Detection[] {
  return mergeDetections(
    detectNamedGroup(text, /\/(?:Users|home)\/(?<value>[^/\s]+)(?=\/)/g, {
      kind: 'LOCAL_USER',
    }),
    detectNamedGroup(text, /\b[A-Za-z]:\\Users\\(?<value>[^\\\s]+)(?=\\)/g, {
      kind: 'LOCAL_USER',
      canonicalize: (value) => value.toLowerCase(),
    }),
  );
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
  const detections = detectNamedGroup(
    text,
    /["']?(?:user|account|customer|session|request|trace|device)[_-]?id["']?\s*(?:=|:)\s*(?<value>"[^"\r\n]*"|'[^'\r\n]*'|[A-Za-z0-9._:-]{4,})/gi,
    { kind: 'IDENTIFIER' },
  );

  return detections
    .map(stripMatchingQuotes)
    .filter((detection): detection is Detection => detection !== null)
    .map((detection) => ({ ...detection, confidence: 'medium' as const }));
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
