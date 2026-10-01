import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

const input = [
  'password="alpha\\"bravo"',
  '{"Authorization":"Bearer synthetic-token"}',
  'Cookie: sid="synthetic"; other=demo',
  'pa\u200bssword=hidden-demo',
  '手机号：13800138000',
  '/Users/Alice',
  'redis://:synthetic-password@localhost:6379/0',
].join('\n');
const expected = [
  'password="<SECRET_1>"',
  '{"Authorization":"Bearer <BEARER_TOKEN_1>"}',
  'Cookie: <COOKIE_1>',
  'password=<SECRET_2>',
  '手机号：<PHONE_1>',
  '/Users/<LOCAL_USER_1>',
  'redis://:<DATABASE_PASSWORD_1>@localhost:6379/0',
].join('\n');

for (const [edition, url] of [
  ['hosted', 'http://127.0.0.1:4173'],
  ['offline', new URL('../../portable/pasteguard-local.html', import.meta.url).href],
]) {
  test(`${edition}: matching, presets, repeated edits, dialog, download, and clear`, async ({ page }) => {
    const errors = [];
    const requests = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => requests.push({ url: request.url(), method: request.method() }));
    await page.goto(url);
    await expect(page.getByRole('heading', { name: 'Make text safe before you share it.' })).toBeVisible();
    await expect(page.locator('#copy-output')).toBeDisabled();
    await page.locator('#source-input').fill(input);
    await expect(page.locator('#output-text')).toHaveValue(expected);

    await page.getByRole('button', { name: 'Secrets only', exact: true }).click();
    await expect(page.locator('#output-text')).toHaveValue(/手机号：13800138000/);
    await expect(page.locator('#output-text')).toHaveValue(/\/Users\/Alice/);
    await page.getByRole('button', { name: 'Balanced', exact: true }).click();
    await expect(page.locator('#output-text')).toHaveValue(expected);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      await page.locator('#open-rules').click();
      await expect(page.locator('#rules-dialog')).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(page.locator('#rules-dialog')).not.toBeVisible();
    }

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#download-output').click();
    const download = await downloadPromise;
    expect(await readFile(await download.path(), 'utf8')).toBe(expected);

    // Re-sanitizing output must retain placeholders without collisions or renumbering.
    await page.locator('#source-input').fill(expected);
    await expect(page.locator('#output-text')).toHaveValue(expected);
    await page.locator('#source-input').fill('password=second-demo');
    await expect(page.locator('#output-text')).toHaveValue('password=<SECRET_1>');
    await page.locator('#clear-input').click();
    await expect(page.locator('#source-input')).toHaveValue('');
    await expect(page.locator('#output-text')).toHaveValue('');
    await expect(page.locator('#copy-output')).toBeDisabled();

    await page.locator('#source-input').fill(input);
    await expect(page.locator('#output-text')).toHaveValue(expected);
    await page.reload();
    await expect(page.locator('#source-input')).toHaveValue('');
    await expect(page.locator('#output-text')).toHaveValue('');
    expect(errors).toEqual([]);
    expect(requests.every((request) => request.method === 'GET')).toBe(true);
    if (edition === 'offline') {
      expect(requests.some((request) => /^https?:/.test(request.url))).toBe(false);
    } else {
      expect(requests.every((request) => new URL(request.url).origin === 'http://127.0.0.1:4173')).toBe(true);
    }
  });
}

test('offline compatibility copy is identical to the canonical app', async () => {
  const canonical = await readFile(fileURLToPath(new URL('../../portable/pasteguard-local.html', import.meta.url)));
  const compatibility = await readFile(fileURLToPath(new URL('../../sharesafe-local.html', import.meta.url)));
  expect(canonical.equals(compatibility)).toBe(true);
});
