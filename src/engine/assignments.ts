import type { Detection } from './types.js';

export interface AssignmentValue {
  key: string;
  start: number;
  end: number;
  value: string;
}

// Match whole keys rather than suffixes (notpassword and token_count are not secrets).
// Only horizontal whitespace is allowed: an empty setting must not eat the next line.
const ASSIGNMENT = /(?<![\w$.-])(?:(["'])([A-Za-z_][\w.-]*)\1|([A-Za-z_][\w.-]*))[\t ]*(?:=|:)[\t ]*/g;

export function normalizedKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().replace(/[.-]/g, '_');
}

export function isRedactedPlaceholder(value: string): boolean {
  return /^<[A-Z][A-Z_]*_\d+>$/.test(value);
}

export function assignmentValues(
  text: string,
  acceptsKey: (key: string) => boolean,
  headerValue: false | 'cookie' | 'authorization' = false,
): AssignmentValue[] {
  const values: AssignmentValue[] = [];
  let consumedUntil = 0;
  for (const match of text.matchAll(ASSIGNMENT)) {
    if (match.index < consumedUntil) {
      continue;
    }
    // Query parameters have their own separator-aware detector. Treating them as
    // assignments could consume following public parameters as part of a secret.
    if (/[?&]$|&amp;$/.test(text.slice(Math.max(0, match.index - 5), match.index))) {
      continue;
    }
    const key = match[2] ?? match[3] ?? '';
    if (!acceptsKey(key)) {
      continue;
    }
    let start = match.index + match[0].length;
    let end = start;
    const quote = text[start];
    if (headerValue === 'authorization' && quote !== '"' && quote !== "'" && quote !== '`') {
      // Read only the scheme and credential, not the remainder of a log line.
      const credential = /(?:Bearer|Basic|Token)[\t ]+[A-Za-z0-9._~+/=-]+/iy;
      credential.lastIndex = start;
      if (!credential.exec(text)) {
        continue;
      }
      end = credential.lastIndex;
    } else if (quote === '"' || quote === "'" || quote === '`') {
      start += 1;
      end = start;
      while (end < text.length && text[end] !== '\r' && text[end] !== '\n') {
        if (text[end] === '\\' && end + 1 < text.length && !/[\r\n]/.test(text[end + 1] ?? '')) {
          end += 2;
        } else if (text[end] === quote) {
          // YAML single-quoted strings escape a quote by doubling it.
          if (quote === "'" && text[end + 1] === "'") {
            end += 2;
          } else {
            break;
          }
        } else {
          end += 1;
        }
      }
    } else {
      // Only the actual surrounding curl quote terminates a raw header. A
      // Cookie value can itself contain quotes (sid="synthetic").
      const beforeKey = text[match.index - 1];
      const enclosingQuote = headerValue && !match[1] &&
        (beforeKey === '"' || beforeKey === "'" || beforeKey === '`') ? beforeKey : undefined;
      const terminator = headerValue ? /[\r\n]/ : /[\s,;#}\]"'`]/;
      while (end < text.length && !terminator.test(text[end] ?? '')) {
        if (enclosingQuote && text[end] === enclosingQuote) {
          break;
        }
        if (enclosingQuote && text[end] === '\\' && text[end + 1] === enclosingQuote) {
          end += 2;
        } else {
          end += 1;
        }
      }
      while (end > start && /[\t ]/.test(text[end - 1] ?? '')) {
        end -= 1;
      }
    }
    if (end > start) {
      consumedUntil = end;
      const value = text.slice(start, end);
      if (!isRedactedPlaceholder(value)) {
        values.push({ key, start, end, value });
      }
    }
  }
  return values;
}

export function assignmentDetection(value: AssignmentValue, kind: string): Detection {
  return { start: value.start, end: value.end, value: value.value, kind };
}
