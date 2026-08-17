export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Category =
  | 'secrets'
  | 'personal'
  | 'network'
  | 'device'
  | 'identifiers'
  | 'hygiene';

export type Confidence = 'high' | 'medium';

export interface Detection {
  start: number;
  end: number;
  value: string;
  kind: string;
  canonicalValue?: string;
  fixedReplacement?: string;
  confidence?: Confidence;
}

export interface Rule {
  id: string;
  label: string;
  description: string;
  category: Category;
  severity: Severity;
  priority: number;
  enabledByDefault: boolean;
  detect: (text: string) => Detection[];
}

export interface Finding {
  id: string;
  ruleId: string;
  label: string;
  description: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  start: number;
  end: number;
  line: number;
  column: number;
  originalPreview: string;
  replacement: string;
}

export interface SanitizationResult {
  text: string;
  findings: Finding[];
  enabledRuleIds: string[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    changedCharacters: number;
  };
}

export interface Preset {
  id: string;
  label: string;
  description: string;
  ruleIds: string[];
}
