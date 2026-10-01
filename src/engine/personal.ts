import { passesLuhn } from './luhn.js';
import type { Detection } from './types.js';

/** Home-path components only: this deliberately does not guess usernames in arbitrary paths. */
export function detectLocalUsernames(text: string): Detection[] {
  const prefixes = /\/(?:Users|home)\/|[A-Za-z]:\\{1,2}[Uu][Ss][Ee][Rr][Ss]\\{1,2}/g;
  const detections: Detection[] = [];

  for (const match of text.matchAll(prefixes)) {
    const pathStart = match.index;
    const before = text[pathStart - 1] ?? '';
    // Avoid relative paths, URL path segments, and names embedded in identifiers.
    if (before && !/[\s"'`=:(\[{]/.test(before)) {
      continue;
    }

    const windows = /^[A-Za-z]:/.test(match[0]);
    let start = pathStart + match[0].length;
    const componentQuote = /["'`]/.test(text[start] ?? '') ? text[start] : undefined;
    const pathQuote = /["'`]/.test(before) ? before : undefined;
    const quote = componentQuote ?? pathQuote;
    if (componentQuote) {
      start += 1;
    }

    let limit = text.length;
    if (quote) {
      const quoteEnd = text.indexOf(quote, start);
      // An unfinished quote cannot establish a spaced username, but an obvious
      // unspaced component followed by a path separator is still safe to identify.
      if (quoteEnd < 0 || /[\r\n]/.test(text.slice(start, quoteEnd))) {
        const nextBoundary = text.slice(start).search(/[\/\\\s]/);
        if (nextBoundary < 0 || !/[\/\\]/.test(text[start + nextBoundary] ?? '')) {
          continue;
        }
        limit = start + nextBoundary;
      } else {
        limit = quoteEnd;
      }
    }

    let end = start;
    while (end < limit) {
      const character = text[end] ?? '';
      if (character === '/' || character === '\\' || /[\r\n]/.test(character)) {
        break;
      }
      if (!quote && /[\s"'`<>|?*:,;()\[\]{}]/.test(character)) {
        break;
      }
      end += 1;
    }

    // In unquoted prose, sentence punctuation belongs to the surrounding text.
    if (!quote && text[end] !== '/' && text[end] !== '\\') {
      while (end > start && /[.!]/.test(text[end - 1] ?? '')) {
        end -= 1;
      }
    }

    const value = text.slice(start, end);
    if (
      !value ||
      value === '.' ||
      value === '..' ||
      value.trim() !== value ||
      !/^[\p{L}\p{N}_.@$-]+(?: [\p{L}\p{N}_.@$'-]+)*$/u.test(value)
    ) {
      continue;
    }

    detections.push({
      start,
      end,
      value,
      canonicalValue: windows ? value.toLowerCase() : value,
      kind: 'LOCAL_USER',
    });
  }

  return detections;
}

function hasPersonalPhoneContext(text: string, start: number): boolean {
  // Keep the label adjacent to the value. A mention of "phone" elsewhere is not evidence.
  return /(?:^|[^\p{L}\p{N}_-])["']?(?:phone(?:[ _-]?number)?|mobile(?:[ _-]?number)?|tel(?:ephone)?(?:[ _-]?number)?|cell(?:[ _-]?phone)?(?:[ _-]?number)?|手机(?:号码?)?|电话(?:号码)?|联系电话)["']?[ \t]*(?:[:=：][ \t]*|[ \t]+)["']?$/iu.test(
    text.slice(Math.max(0, start - 100), start),
  );
}

const personalNorthAmericanPhone = '(?:\\+?1[ .-]?)?(?:\\([2-9]\\d{2}\\)[ ]?[2-9]\\d{2}[ .-]?\\d{4}|[2-9]\\d{2}[ .-][2-9]\\d{2}[ .-]\\d{4})';
const personalNorthAmericanShape = new RegExp(`^${personalNorthAmericanPhone}$`);

function hasPersonalPhoneShape(value: string): boolean {
  if (/^\+[1-9]/.test(value)) {
    return true;
  }
  // Common North American and trunk-prefixed international grouping. Bare digit strings
  // need an explicit label; these shapes are a heuristic, not worldwide phone validation.
  return personalNorthAmericanShape.test(value) ||
    /^0\d{1,4}[ -]\d{3,4}[ -]\d{3,4}$/.test(value);
}

function hasPersonalPhoneDelimiters(value: string): boolean {
  // Keep digit runs separated in these expressions to avoid exponential backtracking
  // on long numeric strings followed by malformed punctuation.
  const withoutPlus = value.replace(/^\+/, '');
  return /^\d+(?:[ .-]\d+)*$/.test(withoutPlus) ||
    /^(?:\d+[ .-]?)?\(\d{1,4}\)[ .-]?\d+(?:[ .-]\d+)*$/.test(withoutPlus);
}

function isPersonalNonPhoneContext(text: string, start: number): boolean {
  return /(?:^|[^\p{L}\p{N}_-])["']?(?:version|build(?:[ _-]?(?:id|number))?|(?:user|order|account|request|customer|device|session|trace|ticket)?[ _-]?id|date|timestamp|ip(?:v4|[ _-]?address)?|订单号|编号)["']?[ \t]*[:=：][ \t]*["']?$/iu.test(
    text.slice(Math.max(0, start - 100), start),
  );
}

function createPersonalPhoneDetection(text: string, start: number, value: string): Detection | null {
  const end = start + value.length;
  const before = text[start - 1] ?? '';
  const after = text[end] ?? '';
  const digits = value.replace(/\D/g, '');
  const context = hasPersonalPhoneContext(text, start);
  const embedded = /[\p{L}\p{N}_+.-]/u.test(before) || /[\p{L}\p{N}_+-]/u.test(after) ||
    (after === '.' && /\d/.test(text[end + 1] ?? ''));
  const date = /^(?:\d{4}[-.]\d{1,2}[-.]\d{1,2}|\d{1,2}[-.]\d{1,2}[-.]\d{2,4})(?:$| )/.test(value);
  const ip = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);

  if (
    digits.length < 7 ||
    digits.length > 15 ||
    /^(\d)\1+$/.test(digits) ||
    embedded ||
    date ||
    ip ||
    isPersonalNonPhoneContext(text, start) ||
    !hasPersonalPhoneDelimiters(value) ||
    (!context && !hasPersonalPhoneShape(value)) ||
    passesLuhn(value)
  ) {
    return null;
  }

  return {
    start,
    end,
    value,
    canonicalValue: digits,
    kind: 'PHONE',
    confidence: 'medium',
  };
}

export function detectPhoneNumbers(text: string): Detection[] {
  // Consume the whole numeric run before validating it. This prevents a long ID, date,
  // or dotted version from being redacted as a shorter plausible telephone substring.
  const candidates = /(?:\+\d|\(\d{1,4}\)|\d)[\d ().-]*\d/g;
  const detections: Detection[] = [];

  for (const match of text.matchAll(candidates)) {
    const detection = createPersonalPhoneDetection(text, match.index, match[0]);
    if (detection) {
      detections.push(detection);
    }
  }

  // A broad numeric run can contain two adjacent US phone numbers. Recognize their
  // complete, fixed-length shapes separately instead of merging or truncating them.
  const separateDetections: Detection[] = [];
  let broadIndex = 0;
  for (const match of text.matchAll(new RegExp(personalNorthAmericanPhone, 'g'))) {
    const detection = createPersonalPhoneDetection(text, match.index, match[0]);
    if (!detection) {
      continue;
    }
    while (broadIndex < detections.length && (detections[broadIndex]?.end ?? 0) <= detection.start) {
      broadIndex += 1;
    }
    const existing = detections[broadIndex];
    if (!existing || existing.start >= detection.end) {
      separateDetections.push(detection);
    }
  }

  return detections.concat(separateDetections).sort((left, right) => left.start - right.start);
}
