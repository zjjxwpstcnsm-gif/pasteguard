import { APP_NAME, APP_VERSION } from './config.js';
import {
  DEFAULT_PRESET_ID,
  PRESETS,
  RULES,
  sanitize,
  type Category,
  type Finding,
  type Preset,
  type SanitizationResult,
} from './engine/index.js';

const SAMPLE_TEXT = `POST https://api.example.com/v1/orders?token=demo_super_secret_token_123456
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.demo_signature_value
Cookie: session=abc123xyz; csrf=secret-cookie-value

api_key = "sk-demo-4D8fK2mN9qR7sT1vX6yZ"
password: correct-horse-battery-staple
DATABASE_URL=postgresql://demo_user:db-password-123@10.24.5.18:5432/orders

Customer: maya.chen@example.com
Phone: +1 (415) 555-0137
Payment card: 4242 4242 4242 4242
Local file: /Users/maya/work/acme/error.log
Device: 00:1A:2B:3C:4D:5E
requestId: 7a9e6679-7425-40de-944b-e07fc1f90ae7

\u001b[31mERROR\u001b[0m Login failed for maya.chen@example.com from 10.24.5.18
Invisible character: safe\u200Btext`;

const CATEGORY_META: Record<Category, { label: string; description: string }> = {
  secrets: {
    label: 'Secrets and credentials',
    description: 'Keys, tokens, passwords, cookies, and credential-bearing URLs.',
  },
  personal: {
    label: 'Personal data',
    description: 'Email addresses, phone-shaped values, and payment card numbers.',
  },
  network: {
    label: 'Network details',
    description: 'IP and hardware addresses that may expose internal infrastructure.',
  },
  device: {
    label: 'Local device details',
    description: 'Usernames exposed by local filesystem paths.',
  },
  identifiers: {
    label: 'Identifiers',
    description: 'Generic IDs and UUIDs. Disabled in Balanced mode to reduce false positives.',
  },
  hygiene: {
    label: 'Text hygiene',
    description: 'Invisible Unicode controls and terminal formatting sequences.',
  },
};

const sourceInput = getElement<HTMLTextAreaElement>('source-input');
const outputText = getElement<HTMLTextAreaElement>('output-text');
const sourceCount = getElement<HTMLElement>('source-count');
const outputCount = getElement<HTMLElement>('output-count');
const resultStatus = getElement<HTMLElement>('result-status');
const findingsList = getElement<HTMLElement>('findings-list');
const summaryChips = getElement<HTMLElement>('summary-chips');
const presetList = getElement<HTMLElement>('preset-list');
const presetDescription = getElement<HTMLElement>('preset-description');
const enabledRuleCount = getElement<HTMLElement>('enabled-rule-count');
const rulesDialog = getElement<HTMLDialogElement>('rules-dialog');
const rulesContent = getElement<HTMLElement>('rules-content');
const toast = getElement<HTMLElement>('toast');
const sourceCard = getElement<HTMLElement>('source-card');
const dropHint = getElement<HTMLElement>('drop-hint');
const fileInput = getElement<HTMLInputElement>('file-input');
const copyButton = getElement<HTMLButtonElement>('copy-output');
const downloadButton = getElement<HTMLButtonElement>('download-output');

let activePresetId = DEFAULT_PRESET_ID;
let enabledRules = new Set(getPreset(DEFAULT_PRESET_ID).ruleIds);
let currentResult = sanitize('', { enabledRuleIds: enabledRules });
let scheduledFrame = 0;
let toastTimer = 0;

initialize();

function initialize(): void {
  document.title = `${APP_NAME} — Make text safe before you share it`;
  renderPresets();
  renderRules();
  renderResult(currentResult);
  bindEvents();

  if (new URLSearchParams(window.location.search).get('demo') === '1') {
    sourceInput.value = SAMPLE_TEXT;
    runSanitize();
  }

  registerServiceWorker();
}

function bindEvents(): void {
  sourceInput.addEventListener('input', scheduleSanitize);
  outputText.addEventListener('input', updateOutputCount);

  getElement<HTMLButtonElement>('load-sample').addEventListener('click', () => {
    sourceInput.value = SAMPLE_TEXT;
    scheduleSanitize();
    sourceInput.focus();
    showToast('Synthetic sample loaded');
  });

  getElement<HTMLButtonElement>('clear-input').addEventListener('click', () => {
    sourceInput.value = '';
    outputText.value = '';
    scheduleSanitize();
    sourceInput.focus();
  });

  getElement<HTMLButtonElement>('open-rules').addEventListener('click', () => {
    rulesDialog.showModal();
  });

  getElement<HTMLButtonElement>('reset-rules').addEventListener('click', () => {
    applyPreset(DEFAULT_PRESET_ID);
    renderRules();
    showToast('Balanced rules restored');
  });

  getElement<HTMLButtonElement>('open-file').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (file) {
      await loadFile(file);
    }
    fileInput.value = '';
  });

  copyButton.addEventListener('click', copySafeText);
  downloadButton.addEventListener('click', downloadSafeText);

  sourceCard.addEventListener('dragenter', handleDragEnter);
  sourceCard.addEventListener('dragover', handleDragEnter);
  sourceCard.addEventListener('dragleave', handleDragLeave);
  sourceCard.addEventListener('drop', handleDrop);

  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && outputText.value) {
      event.preventDefault();
      void copySafeText();
    }
  });
}

function renderPresets(): void {
  presetList.replaceChildren();

  for (const preset of PRESETS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'preset-button';
    button.textContent = preset.label;
    button.dataset.presetId = preset.id;
    button.setAttribute('aria-pressed', String(activePresetId === preset.id));
    button.addEventListener('click', () => applyPreset(preset.id));
    presetList.append(button);
  }

  updatePresetDescription();
}

function applyPreset(presetId: string): void {
  const preset = getPreset(presetId);
  activePresetId = preset.id;
  enabledRules = new Set(preset.ruleIds);
  renderPresets();
  renderRules();
  scheduleSanitize();
}

function renderRules(): void {
  rulesContent.replaceChildren();

  const categories = Object.keys(CATEGORY_META) as Category[];
  for (const category of categories) {
    const rules = RULES.filter((rule) => rule.category === category);
    if (rules.length === 0) {
      continue;
    }

    const group = document.createElement('section');
    group.className = 'rule-group';

    const header = document.createElement('div');
    header.className = 'rule-group-header';
    const titleWrap = document.createElement('div');
    const title = document.createElement('h3');
    title.textContent = CATEGORY_META[category].label;
    const description = document.createElement('p');
    description.textContent = CATEGORY_META[category].description;
    titleWrap.append(title, description);

    const toggleCategory = document.createElement('button');
    toggleCategory.type = 'button';
    toggleCategory.className = 'text-button';
    const allEnabled = rules.every((rule) => enabledRules.has(rule.id));
    toggleCategory.textContent = allEnabled ? 'Disable all' : 'Enable all';
    toggleCategory.addEventListener('click', () => {
      for (const rule of rules) {
        if (allEnabled) {
          enabledRules.delete(rule.id);
        } else {
          enabledRules.add(rule.id);
        }
      }
      markCustomPreset();
      renderRules();
      scheduleSanitize();
    });

    header.append(titleWrap, toggleCategory);
    group.append(header);

    const list = document.createElement('div');
    list.className = 'rule-list';

    for (const rule of rules) {
      const label = document.createElement('label');
      label.className = 'rule-row';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = enabledRules.has(rule.id);
      checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
          enabledRules.add(rule.id);
        } else {
          enabledRules.delete(rule.id);
        }
        markCustomPreset();
        updateEnabledRuleCount();
        scheduleSanitize();
      });

      const switchVisual = document.createElement('span');
      switchVisual.className = 'switch-visual';
      switchVisual.setAttribute('aria-hidden', 'true');

      const text = document.createElement('span');
      text.className = 'rule-copy';
      const rowTitle = document.createElement('span');
      rowTitle.className = 'rule-title';
      rowTitle.textContent = rule.label;
      const rowDescription = document.createElement('span');
      rowDescription.className = 'rule-description';
      rowDescription.textContent = rule.description;
      text.append(rowTitle, rowDescription);

      const severity = document.createElement('span');
      severity.className = `severity-badge severity-${rule.severity}`;
      severity.textContent = rule.severity;

      label.append(checkbox, switchVisual, text, severity);
      list.append(label);
    }

    group.append(list);
    rulesContent.append(group);
  }

  updateEnabledRuleCount();
}

function markCustomPreset(): void {
  const matchedPreset = PRESETS.find((preset) => setsEqual(enabledRules, new Set(preset.ruleIds)));
  activePresetId = matchedPreset?.id ?? 'custom';
  renderPresets();
}

function updatePresetDescription(): void {
  const preset = PRESETS.find((item) => item.id === activePresetId);
  presetDescription.textContent =
    preset?.description ?? 'Custom profile. Open Rules to inspect or change enabled detectors.';
  updateEnabledRuleCount();
}

function updateEnabledRuleCount(): void {
  enabledRuleCount.textContent = String(enabledRules.size);
}

function scheduleSanitize(): void {
  window.cancelAnimationFrame(scheduledFrame);
  scheduledFrame = window.requestAnimationFrame(runSanitize);
}

function runSanitize(): void {
  currentResult = sanitize(sourceInput.value, { enabledRuleIds: enabledRules });
  outputText.value = currentResult.text;
  renderResult(currentResult);
}

function renderResult(result: SanitizationResult): void {
  sourceCount.textContent = formatCount(sourceInput.value.length, 'character');
  updateOutputCount();
  renderStatus(result);
  renderSummary(result);
  renderFindings(result.findings);

  const hasOutput = outputText.value.length > 0;
  copyButton.disabled = !hasOutput;
  downloadButton.disabled = !hasOutput;
}

function updateOutputCount(): void {
  outputCount.textContent = formatCount(outputText.value.length, 'character');
  const hasOutput = outputText.value.length > 0;
  copyButton.disabled = !hasOutput;
  downloadButton.disabled = !hasOutput;
}

function renderStatus(result: SanitizationResult): void {
  resultStatus.className = '';

  if (!sourceInput.value) {
    resultStatus.textContent = 'Paste text to begin';
    resultStatus.classList.add('status-neutral');
    return;
  }

  if (result.summary.total === 0) {
    resultStatus.textContent = 'No built-in patterns found';
    resultStatus.classList.add('status-clear');
    return;
  }

  resultStatus.textContent = `${formatCount(result.summary.total, 'finding')} replaced`;
  resultStatus.classList.add(result.summary.critical > 0 ? 'status-alert' : 'status-found');
}

function renderSummary(result: SanitizationResult): void {
  summaryChips.replaceChildren();

  if (result.summary.total === 0) {
    const chip = document.createElement('span');
    chip.className = 'summary-chip summary-neutral';
    chip.textContent = '0 findings';
    summaryChips.append(chip);
    return;
  }

  const entries = [
    ['critical', result.summary.critical],
    ['high', result.summary.high],
    ['medium', result.summary.medium],
    ['low', result.summary.low],
  ] as const;

  for (const [severity, count] of entries) {
    if (count === 0) {
      continue;
    }
    const chip = document.createElement('span');
    chip.className = `summary-chip severity-${severity}`;
    chip.textContent = `${count} ${severity}`;
    summaryChips.append(chip);
  }
}

function renderFindings(findings: Finding[]): void {
  findingsList.replaceChildren();

  if (!sourceInput.value) {
    findingsList.append(
      createEmptyState('⌁', 'No text yet', 'Paste content above or load the sample to see how redaction works.'),
    );
    return;
  }

  if (findings.length === 0) {
    findingsList.append(
      createEmptyState(
        '✓',
        'No built-in patterns found',
        'That is a useful signal, not a security guarantee. Review the text before sharing.',
      ),
    );
    return;
  }

  const visibleFindings = findings.slice(0, 100);
  for (const finding of visibleFindings) {
    const row = document.createElement('article');
    row.className = 'finding-row';

    const icon = document.createElement('span');
    icon.className = `finding-icon severity-${finding.severity}`;
    icon.textContent = finding.severity === 'critical' ? '!' : finding.severity === 'high' ? '↑' : '•';
    icon.setAttribute('aria-hidden', 'true');

    const main = document.createElement('div');
    main.className = 'finding-main';

    const top = document.createElement('div');
    top.className = 'finding-topline';
    const title = document.createElement('h3');
    title.textContent = finding.label;
    const location = document.createElement('span');
    location.textContent = `Line ${finding.line}, col ${finding.column}`;
    top.append(title, location);

    const description = document.createElement('p');
    description.textContent = finding.description;

    const details = document.createElement('div');
    details.className = 'finding-details';
    const original = document.createElement('code');
    original.textContent = finding.originalPreview;
    const arrow = document.createElement('span');
    arrow.textContent = '→';
    arrow.setAttribute('aria-hidden', 'true');
    const replacement = document.createElement('code');
    replacement.textContent = finding.replacement || '[removed]';
    details.append(original, arrow, replacement);

    main.append(top, description, details);

    const metadata = document.createElement('div');
    metadata.className = 'finding-meta';
    const severity = document.createElement('span');
    severity.className = `severity-badge severity-${finding.severity}`;
    severity.textContent = finding.severity;
    const confidence = document.createElement('span');
    confidence.className = 'confidence-label';
    confidence.textContent = `${finding.confidence} confidence`;
    metadata.append(severity, confidence);

    row.append(icon, main, metadata);
    findingsList.append(row);
  }

  if (findings.length > visibleFindings.length) {
    const remainder = document.createElement('p');
    remainder.className = 'findings-remainder';
    remainder.textContent = `${findings.length - visibleFindings.length} additional findings are hidden from this list. All replacements were still applied.`;
    findingsList.append(remainder);
  }
}

function createEmptyState(iconText: string, titleText: string, descriptionText: string): HTMLElement {
  const state = document.createElement('div');
  state.className = 'empty-state';
  const icon = document.createElement('span');
  icon.className = 'empty-icon';
  icon.textContent = iconText;
  icon.setAttribute('aria-hidden', 'true');
  const title = document.createElement('h3');
  title.textContent = titleText;
  const description = document.createElement('p');
  description.textContent = descriptionText;
  state.append(icon, title, description);
  return state;
}

async function copySafeText(): Promise<void> {
  if (!outputText.value) {
    return;
  }

  try {
    await navigator.clipboard.writeText(outputText.value);
  } catch {
    outputText.select();
    document.execCommand('copy');
    outputText.setSelectionRange(0, 0);
  }

  showToast('Sanitized text copied');
}

function downloadSafeText(): void {
  if (!outputText.value) {
    return;
  }

  const blob = new Blob([outputText.value], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'pasteguard-output.txt';
  anchor.click();
  URL.revokeObjectURL(url);
  showToast('Sanitized text downloaded');
}

async function loadFile(file: File): Promise<void> {
  const maxBytes = 2 * 1024 * 1024;
  if (file.size > maxBytes) {
    showToast('File is larger than the 2 MB browser limit');
    return;
  }

  try {
    sourceInput.value = await file.text();
    scheduleSanitize();
    showToast(`${file.name} loaded locally`);
  } catch {
    showToast('Could not read that file');
  }
}

function handleDragEnter(event: DragEvent): void {
  event.preventDefault();
  sourceCard.classList.add('is-dragging');
  dropHint.classList.add('visible');
}

function handleDragLeave(event: DragEvent): void {
  if (event.relatedTarget instanceof Node && sourceCard.contains(event.relatedTarget)) {
    return;
  }
  sourceCard.classList.remove('is-dragging');
  dropHint.classList.remove('visible');
}

function handleDrop(event: DragEvent): void {
  event.preventDefault();
  sourceCard.classList.remove('is-dragging');
  dropHint.classList.remove('visible');
  const file = event.dataTransfer?.files[0];
  if (file) {
    void loadFile(file);
  }
}

function showToast(message: string): void {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add('visible');
  toastTimer = window.setTimeout(() => toast.classList.remove('visible'), 2200);
}

function registerServiceWorker(): void {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      void navigator.serviceWorker.register('./sw.js').catch(() => {
        // Offline support is optional; the sanitizer remains fully functional.
      });
    });
  }
}

function getPreset(id: string): Preset {
  return PRESETS.find((preset) => preset.id === id) ?? PRESETS[0]!;
}

function formatCount(count: number, singular: string): string {
  return `${count.toLocaleString()} ${singular}${count === 1 ? '' : 's'}`;
}

function setsEqual(left: Set<string>, right: Set<string>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing required element: #${id}`);
  }
  return element as T;
}

console.info(`${APP_NAME} ${APP_VERSION} ready. All text processing is local.`);
