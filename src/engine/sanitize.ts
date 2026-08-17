import { PlaceholderRegistry } from './placeholders.js';
import { RULES } from './rules.js';
import type { Detection, Finding, Rule, SanitizationResult, Severity } from './types.js';

interface Candidate extends Detection {
  rule: Rule;
}

export interface SanitizeOptions {
  enabledRuleIds?: Iterable<string>;
}

export function sanitize(text: string, options: SanitizeOptions = {}): SanitizationResult {
  const enabledRuleIds = new Set(
    options.enabledRuleIds ?? RULES.filter((rule) => rule.enabledByDefault).map((rule) => rule.id),
  );

  if (text.length === 0) {
    return emptyResult([...enabledRuleIds]);
  }

  const candidates = collectCandidates(text, enabledRuleIds);
  const selected = selectNonOverlapping(candidates);
  const registry = new PlaceholderRegistry();
  const lineStarts = createLineStarts(text);

  const replacements = selected
    .sort((left, right) => left.start - right.start || left.end - right.end)
    .map((candidate) => {
      const canonicalValue = candidate.canonicalValue ?? candidate.value;
      const replacement =
        candidate.fixedReplacement ?? registry.get(candidate.kind, canonicalValue);
      const location = locate(lineStarts, candidate.start);

      const finding: Finding = {
        id: `${candidate.rule.id}:${candidate.start}:${candidate.end}`,
        ruleId: candidate.rule.id,
        label: candidate.rule.label,
        description: candidate.rule.description,
        category: candidate.rule.category,
        severity: candidate.rule.severity,
        confidence: candidate.confidence ?? 'high',
        start: candidate.start,
        end: candidate.end,
        line: location.line,
        column: location.column,
        originalPreview: previewValue(candidate),
        replacement,
      };

      return { candidate, replacement, finding };
    });

  const output: string[] = [];
  let cursor = 0;
  for (const item of replacements) {
    output.push(text.slice(cursor, item.candidate.start));
    output.push(item.replacement);
    cursor = item.candidate.end;
  }
  output.push(text.slice(cursor));

  const findings = replacements.map((item) => item.finding);
  return {
    text: output.join(''),
    findings,
    enabledRuleIds: RULES.filter((rule) => enabledRuleIds.has(rule.id)).map((rule) => rule.id),
    summary: {
      total: findings.length,
      critical: countSeverity(findings, 'critical'),
      high: countSeverity(findings, 'high'),
      medium: countSeverity(findings, 'medium'),
      low: countSeverity(findings, 'low'),
      changedCharacters: selected.reduce(
        (total, candidate) => total + (candidate.end - candidate.start),
        0,
      ),
    },
  };
}

function emptyResult(enabledRuleIds: string[]): SanitizationResult {
  return {
    text: '',
    findings: [],
    enabledRuleIds,
    summary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      changedCharacters: 0,
    },
  };
}

function collectCandidates(text: string, enabledRuleIds: Set<string>): Candidate[] {
  const candidates: Candidate[] = [];

  for (const rule of RULES) {
    if (!enabledRuleIds.has(rule.id)) {
      continue;
    }

    let detections: Detection[];
    try {
      detections = rule.detect(text);
    } catch (error) {
      console.warn(`PasteGuard rule failed: ${rule.id}`, error);
      continue;
    }

    for (const detection of detections) {
      if (
        !Number.isInteger(detection.start) ||
        !Number.isInteger(detection.end) ||
        detection.start < 0 ||
        detection.end > text.length ||
        detection.end <= detection.start
      ) {
        continue;
      }

      candidates.push({ ...detection, rule });
    }
  }

  return candidates;
}

function selectNonOverlapping(candidates: Candidate[]): Candidate[] {
  const ranked = [...candidates].sort((left, right) => {
    const priority = right.rule.priority - left.rule.priority;
    if (priority !== 0) {
      return priority;
    }

    const length = right.end - right.start - (left.end - left.start);
    if (length !== 0) {
      return length;
    }

    return left.start - right.start;
  });

  const selected: Candidate[] = [];
  for (const candidate of ranked) {
    const overlaps = selected.some(
      (existing) => candidate.start < existing.end && existing.start < candidate.end,
    );
    if (!overlaps) {
      selected.push(candidate);
    }
  }

  return selected;
}

function countSeverity(findings: Finding[], severity: Severity): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

function createLineStarts(text: string): number[] {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') {
      starts.push(index + 1);
    }
  }
  return starts;
}

function locate(lineStarts: number[], offset: number): { line: number; column: number } {
  let low = 0;
  let high = lineStarts.length - 1;

  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const current = lineStarts[middle];
    const next = lineStarts[middle + 1] ?? Number.POSITIVE_INFINITY;

    if (current === undefined) {
      break;
    }
    if (offset < current) {
      high = middle - 1;
    } else if (offset >= next) {
      low = middle + 1;
    } else {
      return { line: middle + 1, column: offset - current + 1 };
    }
  }

  return { line: 1, column: offset + 1 };
}

function previewValue(candidate: Candidate): string {
  const value = candidate.value;
  if (candidate.fixedReplacement === '') {
    return [...value]
      .map((character) => `U+${character.codePointAt(0)?.toString(16).toUpperCase().padStart(4, '0')}`)
      .join(', ');
  }

  if (candidate.rule.category === 'secrets') {
    return `${value.length} character${value.length === 1 ? '' : 's'}`;
  }

  if (candidate.rule.id === 'email') {
    const [local, domain] = value.split('@');
    if (local && domain) {
      return `${local.slice(0, 1)}•••@${domain}`;
    }
  }

  const compact = value.replace(/\s+/g, ' ');
  if (compact.length <= 8) {
    return '•'.repeat(Math.max(4, compact.length));
  }

  return `${compact.slice(0, 3)}…${compact.slice(-2)} (${compact.length} chars)`;
}
