export class PlaceholderRegistry {
  private readonly values = new Map<string, Map<string, number>>();
  private readonly reserved = new Set<string>();
  private readonly nextIndexes = new Map<string, number>();

  constructor(text = '') {
    for (const match of text.matchAll(/<[A-Z][A-Z_]*_\d+>/g)) {
      this.reserved.add(match[0]);
    }
  }

  get(kind: string, value: string): string {
    const normalizedKind = normalizeKind(kind);
    let valuesForKind = this.values.get(normalizedKind);
    if (!valuesForKind) {
      valuesForKind = new Map<string, number>();
      this.values.set(normalizedKind, valuesForKind);
    }

    let index = valuesForKind.get(value);
    if (index === undefined) {
      index = this.nextIndexes.get(normalizedKind) ?? 1;
      while (this.reserved.has(`<${normalizedKind}_${index}>`)) {
        index += 1;
      }
      this.nextIndexes.set(normalizedKind, index + 1);
      valuesForKind.set(value, index);
    }

    return `<${normalizedKind}_${index}>`;
  }
}

function normalizeKind(kind: string): string {
  return kind
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}
