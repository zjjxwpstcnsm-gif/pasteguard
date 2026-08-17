export class PlaceholderRegistry {
  private readonly values = new Map<string, Map<string, number>>();

  get(kind: string, value: string): string {
    const normalizedKind = normalizeKind(kind);
    let valuesForKind = this.values.get(normalizedKind);
    if (!valuesForKind) {
      valuesForKind = new Map<string, number>();
      this.values.set(normalizedKind, valuesForKind);
    }

    let index = valuesForKind.get(value);
    if (index === undefined) {
      index = valuesForKind.size + 1;
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
