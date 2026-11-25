// The consent window of the passkey mode (ADR 0079 § 6): a window of the extension, which a
// page can neither draw nor click. It shows the site as the browser gave it and, for a sign
// in, the accounts the core offers; nothing is sent to the core before a click here. Texts
// are set with textContent only.

import { api } from './lib/actions.js';
import { passkeyMessage } from './lib/passkey.js';

const $ = (id) => document.getElementById(id);
const request = new URLSearchParams(window.location.search).get('r');

function show(id, on = true) {
  $(id).hidden = !on;
}

function say(error) {
  const m = $('message');
  m.textContent = error ? passkeyMessage(error) : '';
  m.classList.toggle('alert', Boolean(error));
  m.hidden = !error;
}

async function send(message) {
  try {
    return await api.runtime.sendMessage({ ...message, request });
  } catch {
    return { done: true, gone: true };
  }
}

async function choose(choice, index) {
  for (const b of document.querySelectorAll('button')) b.disabled = true;
  const r = await send({ consent: 'answer', choice, index });
  if (r?.done) {
    window.close();
    return;
  }
  for (const b of document.querySelectorAll('button')) b.disabled = false;
  say(r?.error ?? 'error');
  show('retry', true);
}

function renderAccounts(candidates) {
  const list = $('accounts');
  list.replaceChildren();
  for (const c of candidates) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'entry';
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.setAttribute('aria-hidden', 'true');
    badge.textContent = ((c.displayName || c.userName || c.title).trim()[0] ?? '?').toUpperCase();
    const names = document.createElement('span');
    names.className = 'names';
    const t = document.createElement('span');
    t.className = 'title';
    t.textContent = c.userName || c.displayName || c.title;
    names.append(t);
    const sub = c.displayName && c.userName ? c.displayName : c.title;
    if (sub && sub !== t.textContent) {
      const u = document.createElement('span');
      u.className = 'user';
      u.textContent = sub;
      names.append(u);
    }
    // With several vaults (ADR 0085), every account says which vault it comes from.
    if (c.alias) {
      const v = document.createElement('span');
      v.className = 'user';
      v.textContent = `Coffre : ${c.alias}`;
      names.append(v);
    }
    const go = document.createElement('span');
    go.className = 'fill';
    go.textContent = 'Utiliser';
    b.append(badge, names, go);
    b.addEventListener('click', () => choose('use', c.index));
    li.append(b);
    list.append(li);
  }
  list.querySelector('button')?.focus();
}

async function load() {
  const d = await send({ consent: 'details' });
  if (!d || d.gone) {
    window.close();
    return;
  }
  $('origin').textContent = d.origin;
  $('site-note').textContent =
    d.rpId === new URL(d.origin).hostname ? 'Site vu par le navigateur, en https' : `Domaine de la clé : ${d.rpId}`;
  say(d.error);
  show('retry', Boolean(d.error));
  if (d.kind === 'create') {
    $('heading').textContent = 'Nouvelle clé d’accès';
    $('create-name').textContent = d.rpName || d.rpId;
    $('create-user').textContent = d.userName || d.displayName || '';
    show('create', !d.error);
    show('use', !d.error);
    if (!d.error) $('use').focus();
  } else {
    $('heading').textContent = 'Connexion par clé d’accès';
    renderAccounts(d.candidates ?? []);
    show('choose', !d.error && d.candidates.length > 0);
  }
}

$('use').addEventListener('click', () => choose('use', 0));
$('retry').addEventListener('click', () => {
  show('retry', false);
  load();
});
$('other').addEventListener('click', () => choose('other'));
$('cancel').addEventListener('click', () => choose('cancel'));
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') choose('cancel');
});

// Keeps the background script alive while the user decides.
setInterval(() => {
  send({ consent: 'ping' });
}, 20_000);

load();
