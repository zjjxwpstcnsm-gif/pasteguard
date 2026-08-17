import type { Detection } from './types.js';

type MatchIndices = Array<[number, number] | undefined> & {
  groups?: Record<string, [number, number] | undefined>;
};

type IndexedRegExpExecArray = RegExpExecArray & {
  indices?: MatchIndices;
};

export interface NamedGroupDetectionOptions {
  group?: string;
  kind: string;
  canonicalize?: (value: string) => string;
  fixedReplacement?: string;
}

function withRequiredFlags(expression: RegExp): RegExp {
  const flags = new Set(expression.flags.split(''));
  flags.add('g');
  flags.add('d');
  return new RegExp(expression.source, [...flags].join(''));
}

export function detectNamedGroup(
  text: string,
  expression: RegExp,
  options: NamedGroupDetectionOptions,
): Detection[] {
  const regex = withRequiredFlags(expression);
  const group = options.group ?? 'value';
  const detections: Detection[] = [];

  let match: IndexedRegExpExecArray | null;
  while ((match = regex.exec(text) as IndexedRegExpExecArray | null) !== null) {
    const range = match.indices?.groups?.[group];
    if (!range) {
      continue;
    }

    const [start, end] = range;
    const value = text.slice(start, end);
    if (!value) {
      continue;
    }

    const detection: Detection = {
      start,
      end,
      value,
      kind: options.kind,
    };

    const canonicalValue = options.canonicalize?.(value);
    if (canonicalValue !== undefined) {
      detection.canonicalValue = canonicalValue;
    }
    if (options.fixedReplacement !== undefined) {
      detection.fixedReplacement = options.fixedReplacement;
    }

    detections.push(detection);
  }

  return detections;
}

export function detectWholeMatch(
  text: string,
  expression: RegExp,
  kind: string,
  fixedReplacement?: string,
): Detection[] {
  const regex = withRequiredFlags(expression);
  const detections: Detection[] = [];

  let match: IndexedRegExpExecArray | null;
  while ((match = regex.exec(text) as IndexedRegExpExecArray | null) !== null) {
    const range = match.indices?.[0];
    if (!range || !match[0]) {
      continue;
    }

    const detection: Detection = {
      start: range[0],
      end: range[1],
      value: match[0],
      kind,
    };
    if (fixedReplacement !== undefined) {
      detection.fixedReplacement = fixedReplacement;
    }
    detections.push(detection);
  }

  return detections;
}

export function mergeDetections(...groups: Detection[][]): Detection[] {
  return groups.flat();
}
