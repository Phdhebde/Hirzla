// What the popup does, each step on an explicit click of the user in the popup (browser UI
// that a web page can neither draw over nor click). Nothing here runs on its own: the
// extension has no background script and no content script.
//
// Secrets only transit: a password received from the host is handed to the page and the
// reference dropped; nothing is written to extension storage (no storage permission).

import { checkInjection, sanitizeEntries, alreadySaved } from './decide.js';
import { originOfUrl, hostOf } from './origin.js';
import { pageAgent } from './page.js';

/** Name of the native messaging host (docs: apps/extension/README.md). */
export const HOST = 'hirzla.native_host';

/** WebExtension API: `browser` on Firefox, `chrome` on Chromium (both promise-based in MV3). */
export const api = globalThis.browser ?? globalThis.chrome;

/**
 * One message to the native host; the browser starts it for the message.
 * @param {object} message
 * @returns {Promise<{ok: boolean, error?: string, [k: string]: unknown}>}
 */
export async function ask(message) {
  let reply;
  try {
    reply = await api.runtime.sendNativeMessage(HOST, message);
  } catch {
    return { ok: false, error: 'host_unavailable' };
  }
  if (!reply || typeof reply !== 'object' || typeof reply.ok !== 'boolean') {
    return { ok: false, error: 'host_error' };
  }
  if (!reply.ok && typeof reply.error !== 'string') return { ok: false, error: 'host_error' };
  return reply;
}

/** The canonical https origin of a tab, from the browser, or null. */
export function tabOrigin(tab) {
  return tab && typeof tab.url === 'string' ? originOfUrl(tab.url) : null;
}

/**
 * Runs the page agent in the main frame (frame 0) of `tabId` only, after checking that the
 * tab still shows `origin`. The answer counts only if it comes from frame 0 and the page says
 * it is the top-level document of `origin`.
 */
async function runInMainFrame(tabId, origin, action, data) {
  let tab;
  try {
    tab = await api.tabs.get(tabId);
  } catch {
    return { ok: false, reason: 'navigated' };
  }
  if (tabOrigin(tab) !== origin) return { ok: false, reason: 'navigated' };
  let results;
  try {
    results = await api.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: pageAgent,
      args: [action, origin, data ?? null],
    });
  } catch {
    // Firefox and Chromium refuse to inject when the activeTab grant does not cover the
    // document now in the tab (it navigated to another origin).
    return { ok: false, reason: 'navigated' };
  }
  return checkInjection(results, origin);
}

/** The vault state, then the logins registered for the exact origin of `tab`. */
export async function listForTab(tab) {
  const origin = tabOrigin(tab);
  if (!origin) return { ok: false, error: 'unsupported_page' };
  const status = await ask({ type: 'status' });
  if (!status.ok) return status;
  if (status.state === 'absent') return { ok: false, error: 'no_vault', origin };
  if (status.state !== 'unlocked') return { ok: false, error: 'locked', origin };
  const found = await ask({ type: 'match', origin });
  if (!found.ok) return { ...found, origin };
  return { ok: true, origin, entries: sanitizeEntries(found.entries), truncated: found.truncated === true };
}

/**
 * Fills `entry` into the page of `tab`: first checks that the main frame has a visible
 * password field, then asks the host for the login of the exact origin (the core refuses
 * any other), then fills it in the main frame only.
 */
export async function fillForTab(tab, entry) {
  const origin = tabOrigin(tab);
  if (!origin) return { ok: false, error: 'unsupported_page' };
  const probe = await runInMainFrame(tab.id, origin, 'inspect');
  if (!probe.ok) return { ok: false, error: probe.reason };
  const login = await ask({ type: 'fill', origin, locker: entry.locker, id: entry.id });
  if (!login.ok) return { ok: false, error: login.error };
  if (typeof login.password !== 'string') return { ok: false, error: 'host_error' };
  const done = await runInMainFrame(tab.id, origin, 'fill', {
    username: typeof login.username === 'string' ? login.username : null,
    password: login.password,
  });
  return done.ok ? { ok: true } : { ok: false, error: done.reason };
}

/** Reads the login typed in the page of `tab`, to propose saving it. */
export async function readLoginForTab(tab) {
  const origin = tabOrigin(tab);
  if (!origin) return { ok: false, error: 'unsupported_page' };
  const r = await runInMainFrame(tab.id, origin, 'read');
  if (!r.ok) return { ok: false, error: r.reason };
  return {
    ok: true,
    origin,
    title: hostOf(origin),
    username: typeof r.value.username === 'string' && r.value.username !== '' ? r.value.username : null,
    password: r.value.password,
  };
}

/** Puts a generated password into the new-password fields of the page of `tab`. */
export async function useGeneratedForTab(tab, password) {
  const origin = tabOrigin(tab);
  if (!origin) return { ok: false, error: 'unsupported_page' };
  const r = await runInMainFrame(tab.id, origin, 'new_password', { password });
  if (!r.ok) return { ok: false, error: r.reason };
  return {
    ok: true,
    origin,
    title: hostOf(origin),
    username: typeof r.value.username === 'string' && r.value.username !== '' ? r.value.username : null,
  };
}

/**
 * Saves a new login for `origin`, unless one with the same user name already exists there.
 * @param {string} origin
 * @param {{title?: string, username: string | null, password: string}} login
 */
export async function saveLogin(origin, login) {
  if (!originOfUrl(origin)) return { ok: false, error: 'unsupported_page' };
  if (typeof login.password !== 'string' || login.password === '') return { ok: false, error: 'no_password' };
  const found = await ask({ type: 'match', origin });
  if (!found.ok) return found;
  if (alreadySaved(sanitizeEntries(found.entries), login.username)) return { ok: false, error: 'exists' };
  const message = { type: 'save', origin, password: login.password };
  if (login.title) message.title = login.title;
  if (login.username) message.username = login.username;
  return ask(message);
}

/** A password from the core's generator. */
export async function generate(length, symbols) {
  const r = await ask({ type: 'generate', length, symbols });
  if (r.ok && typeof r.password !== 'string') return { ok: false, error: 'host_error' };
  return r;
}

/** Asks the desktop application to bring its window to the front (ADR 0071). */
export function showApp() {
  return ask({ type: 'show' });
}

/** Locks the vault. */
export function lockVault() {
  return ask({ type: 'lock' });
}
