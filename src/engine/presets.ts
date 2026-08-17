import { RULES } from './rules.js';
import type { Preset } from './types.js';

const secretRuleIds = RULES.filter((rule) => rule.category === 'secrets').map((rule) => rule.id);
const defaultRuleIds = RULES.filter((rule) => rule.enabledByDefault).map((rule) => rule.id);
const publicIssueRuleIds = RULES.filter((rule) => rule.id !== 'phone').map((rule) => rule.id);
const allRuleIds = RULES.map((rule) => rule.id);

export const PRESETS: Preset[] = [
  {
    id: 'balanced',
    label: 'Balanced',
    description: 'Secrets, common personal data, network details, paths, and hidden characters.',
    ruleIds: defaultRuleIds,
  },
  {
    id: 'secrets',
    label: 'Secrets only',
    description: 'Credentials and token-like values with the lowest false-positive surface.',
    ruleIds: secretRuleIds,
  },
  {
    id: 'public-issue',
    label: 'Public issue',
    description: 'A stricter profile for GitHub issues, forums, and public support threads.',
    ruleIds: publicIssueRuleIds,
  },
  {
    id: 'strict',
    label: 'Strict',
    description: 'Every built-in detector, including generic identifiers and UUIDs.',
    ruleIds: allRuleIds,
  },
];

export const DEFAULT_PRESET_ID = 'balanced';
