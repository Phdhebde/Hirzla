// Background script (ADR 0079 § 6). It only serves the passkey mode: with the mode off, no
// content script is registered and no page can reach it. With the mode on, it receives the
// `navigator.credentials` requests relayed from the top frame of https pages, takes the
// page's origin from the browser (the message's sender, never the message), asks the user in
// a window of the extension, then asks the core through the native host. The core checks the
// relying party against that origin and holds every key.
//
// Nothing is stored: a pending request lives in memory until the user answers or closes the
// window.

import { ask, api } from './lib/actions.js';
import {
  CONTENT_SCRIPTS,
  ORIGINS,
  SCRIPT_IDS,
  createMessage,
  domErrorFor,
  effectiveRpId,
  revive,
  senderOrigin,
  serializeCreate,
  serializeGet,
} from './lib/passkey.js';

/** Requests waiting for the user, by id. */
const pending = new Map();
let nextId = 1;

const CONSENT_PAGE = 'passkey.html';

function isConsentPage(sender) {
  return (
    sender?.id === api.runtime.id &&
    typeof sender.url === 'string' &&
    sender.url.startsWith(api.runtime.getURL(CONSENT_PAGE))
  );
}

/** Asks the core for the credentials of the request's site. */
async function candidatesFor(p) {
  const m = { type: 'passkey_candidates', origin: p.origin, rpId: p.rpId };
  if (p.request.allow) m.allow = p.request.allow;
  return ask(m);
}

/** What the consent window shows: the site, and for `get` the vault's state and accounts. */
async function details(p) {
  const base = { kind: p.kind, origin: p.origin, rpId: p.rpId };
  if (p.kind === 'create') {
    const status = await ask({ type: 'status' });
    return {
      ...base,
      rpName: p.request.rpName,
      userName: p.request.userName,
      displayName: p.request.displayName,
      error: !status.ok ? status.error : status.state === 'unlocked' ? null : status.state === 'absent' ? 'no_vault' : 'locked',
    };
  }
  const found = await candidatesFor(p);
  if (!found.ok) return { ...base, error: found.error, candidates: [] };
  p.candidates = found.candidates;
  return {
    ...base,
    error: null,
    candidates: found.candidates.map((c, index) => ({
      index,
      title: c.title,
      userName: c.userName ?? null,
      displayName: c.displayName ?? null,
    })),
  };
}

function settle(p, result) {
  pending.delete(p.id);
  p.resolve(result);
}

/** The user's choice in the consent window: does the work, returns what the window shows. */
async function answer(p, choice, index) {
  if (choice === 'cancel') {
    settle(p, { error: 'NotAllowedError' });
    return { done: true };
  }
  if (choice === 'other') {
    settle(p, { fallback: true });
    return { done: true };
  }
  if (choice !== 'use') return { done: false, error: 'bad_request' };
  let reply;
  if (p.kind === 'create') {
    reply = await ask(createMessage(p.origin, p.request));
  } else {
    const c = p.candidates?.[index];
    if (!c) return { done: false, error: 'bad_request' };
    reply = await ask({
      type: 'passkey_assert',
      origin: p.origin,
      rpId: p.rpId,
      challenge: p.request.challenge,
      locker: c.locker,
      id: c.id,
      uv: p.request.uv,
    });
  }
  if (!reply.ok) {
    // Excluded or unsupported: the page learns it now. Locked, verification: the window
    // says what to do and offers to try again.
    if (['credential_excluded', 'algorithm_unsupported', 'invalid_input', 'invalid_origin'].includes(reply.error)) {
      settle(p, { error: domErrorFor(reply.error) });
      return { done: true, error: reply.error };
    }
    return { done: false, error: reply.error };
  }
  const { ok: _ok, ...result } = reply;
  settle(p, { ok: true, ...result });
  return { done: true };
}

/** A request relayed from a page. Resolves with what the page script expects. */
async function fromPage(message, sender) {
  const origin = senderOrigin(sender);
  if (!origin) return { fallback: true };
  const publicKey = revive(message.publicKey);
  const request = message.passkey === 'create' ? serializeCreate(publicKey) : serializeGet(publicKey);
  if (!request) return { fallback: true };
  const p = {
    id: nextId++,
    kind: message.passkey,
    origin,
    rpId: effectiveRpId(request.rpId, origin),
    request,
    windowId: null,
    candidates: null,
  };
  if (p.kind === 'get') {
    // Nothing of Hirzla for this site: the browser's own authenticator, without a window.
    const status = await ask({ type: 'status' });
    if (!status.ok || status.state === 'absent') return { fallback: true };
    if (status.state === 'unlocked') {
      const found = await candidatesFor(p);
      if (!found.ok || found.candidates.length === 0) return { fallback: true };
    }
  }
  const done = new Promise((resolve) => {
    p.resolve = resolve;
  });
  pending.set(p.id, p);
  try {
    const win = await api.windows.create({
      url: api.runtime.getURL(`${CONSENT_PAGE}?r=${p.id}`),
      type: 'popup',
      width: 440,
      height: 560,
      focused: true,
    });
    p.windowId = win?.id ?? null;
  } catch {
    settle(p, { fallback: true });
  }
  return done;
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') return false;
  let work = null;
  if ((message.passkey === 'create' || message.passkey === 'get') && sender?.tab) {
    work = fromPage(message, sender);
  } else if (typeof message.consent === 'string' && isConsentPage(sender)) {
    const p = pending.get(Number(message.request));
    if (!p) {
      work = Promise.resolve({ done: true, gone: true });
    } else if (message.consent === 'details') {
      work = details(p);
    } else if (message.consent === 'answer') {
      work = answer(p, message.choice, Number(message.index));
    } else if (message.consent === 'ping') {
      // Keeps the background script alive while the window is open.
      work = Promise.resolve({ done: false });
    }
  }
  if (!work) return false;
  work.then(sendResponse, () => sendResponse({ fallback: true }));
  return true;
});

// Closing the consent window is a refusal.
api.windows.onRemoved.addListener((windowId) => {
  for (const p of pending.values()) {
    if (p.windowId === windowId) settle(p, { error: 'NotAllowedError' });
  }
});

/** The mode is on only while both the permission and the scripts are there. */
async function reconcile() {
  let granted = false;
  try {
    granted = await api.permissions.contains({ origins: ORIGINS });
  } catch {
    granted = false;
  }
  const registered = await api.scripting
    .getRegisteredContentScripts({ ids: SCRIPT_IDS })
    .catch(() => []);
  if (!granted && registered.length > 0) {
    await api.scripting.unregisterContentScripts({ ids: registered.map((s) => s.id) }).catch(() => {});
  } else if (granted && registered.length > 0 && registered.length < SCRIPT_IDS.length) {
    await api.scripting.unregisterContentScripts({ ids: registered.map((s) => s.id) }).catch(() => {});
    await api.scripting.registerContentScripts(CONTENT_SCRIPTS).catch(() => {});
  }
}

// The user can take the permission back in the browser's settings: the mode goes off.
api.permissions.onRemoved?.addListener(() => {
  reconcile();
});
api.runtime.onStartup?.addListener(() => {
  reconcile();
});
api.runtime.onInstalled?.addListener(() => {
  reconcile();
});
