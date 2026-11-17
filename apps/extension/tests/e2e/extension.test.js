// End-to-end tests: the real extension in Chromium (Playwright, new headless mode), the real
// native host started by the browser, a real hirzla-core and vault. Test pages are served
// by Playwright's router under fictitious https origins (*.test), so nothing leaves the
// machine.
//
// Prerequisites: `cargo build -p hirzla-core -p hirzla-cli -p hirzla-native-host` (binaries
// looked up in HIRZLA_BIN_DIR, default <repo>/target/debug) and Playwright's Chromium.
//
// The only difference with the shipped extension: the test copy gets host permissions on
// *.test, because a test cannot click the toolbar button that grants `activeTab`. The code
// paths are the same; the tab is found by URL instead of being the active one.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const here = path.dirname(fileURLToPath(import.meta.url));
const extRoot = path.resolve(here, '..', '..');
const repo = path.resolve(extRoot, '..', '..');
const bin = process.env.HIRZLA_BIN_DIR ?? path.join(repo, 'target', 'debug');
const exe = (name) => path.join(bin, process.platform === 'win32' ? `${name}.exe` : name);

const MASTER = 'Maître-de-test-extension-7c4e';
const SECRET = 'Secret-Banque-Navigateur-3f9a1d';
const HOST_NAME = 'hirzla.native_host';

let tmp;
let core;
let context;
let extId;
let extPage;
let sock;

function pages(file) {
  return fs.readFileSync(path.join(extRoot, 'tests', 'pages', file), 'utf8');
}

/** URL → page served. Every other request is refused. */
function route(url) {
  const u = new URL(url);
  const key = `${u.protocol}//${u.host}${u.pathname}`;
  const login = pages('login.html');
  const table = {
    'https://bank.test/login': login,
    'https://bank-test.test/login': login,
    'https://banq.test/login': login,
    'https://xn--bnk-6cd.test/login': login, // bаnk.test, with a Cyrillic а
    'https://bank.test.evil.test/login': login,
    'https://login.bank.test/login': login,
    'https://test/login': login,
    'http://bank.test/login': login,
    'https://evil.test/login': login,
    'https://evil.test/': pages('evil-embeds-bank.html'),
    'https://bank.test/embed': pages('bank-embeds-evil.html'),
    'https://bank.test/decoy': pages('decoy.html'),
    'https://shop.test/signup': pages('signup.html'),
  };
  if (u.host === 'bank.test' && u.pathname.startsWith('/hidden/')) {
    return pages('hidden.html').replace('__VARIANT__', u.pathname.slice('/hidden/'.length));
  }
  return table[key] ?? null;
}

function hirzla(args, input) {
  const r = spawnSync(exe('hirzla'), ['--socket', sock, ...args], { input: input ?? '', encoding: 'utf8' });
  return r;
}

/** Chromium's identifier for an unpacked extension: derived from its absolute path. */
function extensionId(dir) {
  return [...createHash('sha256').update(dir).digest('hex').slice(0, 32)]
    .map((c) => String.fromCharCode(97 + Number.parseInt(c, 16)))
    .join('');
}

let counter = 0;
async function open(url) {
  const page = await context.newPage();
  await page.goto(url);
  // A unique marker in the fragment lets the extension page find this tab by URL; the
  // fragment is not part of the origin.
  const marked = `${url}#t${(counter += 1)}`;
  await page.evaluate((m) => history.replaceState(null, '', m), marked);
  return { page, url: page.url() };
}

/** Runs an action of the extension (src/lib/actions.js) on the tab showing `url`. */
function action(name, url, ...args) {
  return extPage.evaluate(
    async ({ name, url, args }) => {
      const a = await import('./lib/actions.js');
      const tabs = await chrome.tabs.query({});
      const tab = tabs.find((t) => t.url === url);
      if (!tab) return { ok: false, error: 'test: tab not found' };
      return a[name](tab, ...args);
    },
    { name, url, args },
  );
}

function ask(message) {
  return extPage.evaluate(async (m) => (await import('./lib/actions.js')).ask(m), message);
}

async function values(page, frameSelector) {
  const target = frameSelector ? page.frameLocator(frameSelector) : page;
  const read = async (sel) => ((await target.locator(sel).count()) ? target.locator(sel).inputValue() : null);
  return { user: await read('#user'), pass: await read('#pass') };
}

before(async () => {
  for (const name of ['hirzla-core', 'hirzla', 'hirzla-native-host']) {
    assert.ok(fs.existsSync(exe(name)), `${exe(name)} missing: run cargo build first`);
  }
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hirzla-ext-')));
  fs.chmodSync(tmp, 0o700);
  sock = path.join(tmp, 'core.sock');

  // The core with its default allow lists: the native host next to it gets the browser
  // profile, the command line the full one.
  core = spawn(exe('hirzla-core'), ['--socket', sock, '--vault', path.join(tmp, 'coffre.hirzla'), '--log', path.join(tmp, 'core.log')], {
    stdio: 'ignore',
  });
  for (let i = 0; ; i += 1) {
    if (hirzla(['status']).status === 0) break;
    assert.ok(i < 200, 'the core did not start');
    await new Promise((r) => setTimeout(r, 100));
  }
  let r = hirzla(['init', '--kdf-memory', '65536', '--kdf-passes', '3'], MASTER);
  assert.equal(r.status, 0, r.stderr);
  r = hirzla(['set', 'Banque', '--identifiant', 'max', '--url', 'https://bank.test/login'], SECRET);
  assert.equal(r.status, 0, r.stderr);

  // Test copy of the extension, with host permissions on the test origins.
  const ext = path.join(tmp, 'extension');
  fs.cpSync(path.join(extRoot, 'src'), ext, { recursive: true });
  const manifest = JSON.parse(fs.readFileSync(path.join(ext, 'manifest.json'), 'utf8'));
  manifest.host_permissions = ['https://*.test/*', 'http://*.test/*', 'https://test/*'];
  fs.writeFileSync(path.join(ext, 'manifest.json'), JSON.stringify(manifest));
  extId = extensionId(ext);

  // Native host manifest, in the profile directory, where Chromium looks for user-level
  // hosts on Linux when it runs with --user-data-dir.
  const profile = path.join(tmp, 'profile');
  fs.mkdirSync(path.join(profile, 'NativeMessagingHosts'), { recursive: true });
  fs.writeFileSync(
    path.join(profile, 'NativeMessagingHosts', `${HOST_NAME}.json`),
    JSON.stringify({
      name: HOST_NAME,
      description: 'Hirzla',
      path: exe('hirzla-native-host'),
      type: 'stdio',
      allowed_origins: [`chrome-extension://${extId}/`],
    }),
  );

  context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: true,
    env: { ...process.env, HIRZLA_SOCKET: sock },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  await context.route(/^https?:\/\/([a-z0-9-]+\.)*test(\/|$)/, (r) => {
    const body = route(r.request().url());
    return body === null ? r.fulfill({ status: 404, body: '' }) : r.fulfill({ contentType: 'text/html; charset=utf-8', body });
  });
  extPage = await context.newPage();
  await extPage.goto(`chrome-extension://${extId}/popup.html`);
});

after(async () => {
  await context?.close();
  core?.kill();
  if (tmp) {
    const log = fs.existsSync(path.join(tmp, 'core.log')) ? fs.readFileSync(path.join(tmp, 'core.log'), 'utf8') : '';
    fs.rmSync(tmp, { recursive: true, force: true });
    // The core's log never holds the master password, the secret, or the sites visited.
    for (const s of [MASTER, SECRET, 'bank.test', 'max']) {
      assert.ok(!log.includes(s), `${s} in the core log`);
    }
  }
});

let bankEntry;

test('the popup loads under its CSP and reports an unsupported page', async () => {
  const page = await context.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(String(e)));
  page.on('console', (m) => m.type() === 'error' && problems.push(m.text()));
  await page.goto(`chrome-extension://${extId}/popup.html`);
  await page.locator('#message:not([hidden])').waitFor();
  // The active tab is the popup itself: not an https page.
  assert.equal(await page.locator('#message').textContent(), 'Hirzla ne remplit que les pages servies en https.');
  assert.deepEqual(problems, []);
  await page.close();
});

test('registered origin: listed, then filled on demand', async () => {
  const { page, url } = await open('https://bank.test/login');
  const list = await action('listForTab', url);
  assert.equal(list.ok, true, JSON.stringify(list));
  assert.equal(list.origin, 'https://bank.test');
  assert.equal(list.entries.length, 1);
  bankEntry = list.entries[0];
  assert.equal(bankEntry.title, 'Banque');
  assert.equal(bankEntry.username, 'max');
  assert.ok(!JSON.stringify(list).includes(SECRET), 'the listing carries no password');
  // Nothing is filled before the user picks an entry.
  assert.deepEqual(await values(page), { user: '', pass: '' });
  const r = await action('fillForTab', url, bankEntry);
  assert.deepEqual(r, { ok: true });
  assert.deepEqual(await values(page), { user: 'max', pass: SECRET });
  await page.close();
});

for (const [label, url] of [
  ['look-alike domain (hyphen)', 'https://bank-test.test/login'],
  ['look-alike domain (letter)', 'https://banq.test/login'],
  ['look-alike domain (homograph, IDN)', 'https://xn--bnk-6cd.test/login'],
  ['registered name as a subdomain of another', 'https://bank.test.evil.test/login'],
  ['subdomain of the registered domain', 'https://login.bank.test/login'],
  ['parent of the registered domain', 'https://test/login'],
]) {
  test(`refused: ${label}`, async () => {
    const { page, url: u } = await open(url);
    const list = await action('listForTab', u);
    assert.equal(list.ok, true, JSON.stringify(list));
    assert.deepEqual(list.entries, []);
    // Even when asked for the registered login by its identifiers, the core refuses.
    const r = await action('fillForTab', u, bankEntry);
    assert.deepEqual(r, { ok: false, error: 'not_found' });
    assert.deepEqual(await values(page), { user: '', pass: '' });
    await page.close();
  });
}

test('refused: the registered domain over http', async () => {
  const { page, url } = await open('http://bank.test/login');
  assert.deepEqual(await action('listForTab', url), { ok: false, error: 'unsupported_page' });
  assert.deepEqual(await action('fillForTab', url, bankEntry), { ok: false, error: 'unsupported_page' });
  // And the host refuses the origin by itself.
  assert.deepEqual(await ask({ type: 'fill', origin: 'http://bank.test', locker: bankEntry.locker, id: bankEntry.id }), {
    ok: false,
    error: 'invalid_origin',
  });
  assert.deepEqual(await values(page), { user: '', pass: '' });
  await page.close();
});

test('refused: third-party page framing the registered login page', async () => {
  const { page, url } = await open('https://evil.test/');
  await page.frameLocator('#frame').locator('#pass').waitFor();
  const list = await action('listForTab', url);
  assert.deepEqual(list.entries, []);
  assert.deepEqual(await action('fillForTab', url, bankEntry), { ok: false, error: 'no_field' });
  assert.deepEqual(await values(page, '#frame'), { user: '', pass: '' });
  await page.close();
});

test('refused: registered page whose password field is in a third-party frame', async () => {
  const { page, url } = await open('https://bank.test/embed');
  await page.frameLocator('#frame').locator('#pass').waitFor();
  assert.equal((await action('listForTab', url)).entries.length, 1);
  assert.deepEqual(await action('fillForTab', url, bankEntry), { ok: false, error: 'no_field' });
  assert.deepEqual(await values(page, '#frame'), { user: '', pass: '' });
  await page.close();
});

for (const variant of ['display', 'visibility', 'opacity', 'faint', 'offscreen', 'tiny', 'clip', 'parent', 'parent-opacity', 'covered']) {
  test(`refused: hidden password field (${variant})`, async () => {
    const { page, url } = await open(`https://bank.test/hidden/${variant}`);
    assert.deepEqual(await action('fillForTab', url, bankEntry), { ok: false, error: 'hidden' });
    assert.deepEqual(await values(page), { user: '', pass: '' });
    await page.close();
  });
}

test('hidden decoy fields around a visible form stay empty', async () => {
  const { page, url } = await open('https://bank.test/decoy');
  assert.deepEqual(await action('fillForTab', url, bankEntry), { ok: true });
  assert.deepEqual(await values(page), { user: 'max', pass: SECRET });
  for (const id of ['decoy-user-1', 'decoy-pass-1', 'decoy-user-2', 'decoy-pass-2']) {
    assert.equal(await page.locator(`#${id}`).inputValue(), '', id);
  }
  await page.close();
});

test('generator, then proposal to save the new login for its exact origin', async () => {
  const { page, url } = await open('https://shop.test/signup');
  await page.fill('#user', 'max@shop.test');
  const gen = await extPage.evaluate(async () => (await import('./lib/actions.js')).generate(24, true));
  assert.equal(gen.ok, true);
  assert.equal([...gen.password].length, 24);
  const used = await action('useGeneratedForTab', url, gen.password);
  assert.deepEqual(used, { ok: true, origin: 'https://shop.test', title: 'shop.test', username: 'max@shop.test' });
  assert.equal(await page.locator('#pass').inputValue(), gen.password);
  assert.equal(await page.locator('#pass2').inputValue(), gen.password);
  const read = await action('readLoginForTab', url);
  assert.equal(read.password, gen.password);
  assert.equal(read.username, 'max@shop.test');
  const saved = await extPage.evaluate(
    async ({ origin, login }) => (await import('./lib/actions.js')).saveLogin(origin, login),
    { origin: read.origin, login: { title: read.title, username: read.username, password: read.password } },
  );
  assert.deepEqual(saved, { ok: true });
  // Saved once only.
  const again = await extPage.evaluate(
    async ({ origin, login }) => (await import('./lib/actions.js')).saveLogin(origin, login),
    { origin: read.origin, login: { title: read.title, username: read.username, password: read.password } },
  );
  assert.deepEqual(again, { ok: false, error: 'exists' });
  const list = await action('listForTab', url);
  assert.deepEqual(
    list.entries.map((e) => [e.title, e.username]),
    [['shop.test', 'max@shop.test']],
  );
  // Not offered anywhere else.
  assert.deepEqual((await action('listForTab', (await open('https://bank.test/login')).url)).entries.length, 1);
  await page.close();
});

test('the browser profile cannot list, read or unlock: only what the host exposes', async () => {
  for (const type of ['list', 'read', 'unlock', 'init', 'delete', 'update', 'shutdown']) {
    assert.deepEqual(await ask({ type }), { ok: false, error: 'bad_request' }, type);
  }
});

test('calling for the application window: the host starts nothing', async () => {
  assert.deepEqual(await ask({ type: 'show' }), { ok: false, error: 'no_app' });
  assert.deepEqual(await ask({ type: 'show', origin: 'https://bank.test' }), { ok: false, error: 'bad_request' });
});

test('locking from the extension; nothing is filled while locked', async () => {
  assert.deepEqual(await ask({ type: 'lock' }), { ok: true });
  const { page, url } = await open('https://bank.test/login');
  assert.deepEqual(await action('listForTab', url), { ok: false, error: 'locked', origin: 'https://bank.test' });
  assert.deepEqual(await action('fillForTab', url, bankEntry), { ok: false, error: 'locked' });
  assert.deepEqual(await values(page), { user: '', pass: '' });
  await page.close();
});
