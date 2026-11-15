// The popup: browser UI opened by the user (toolbar button or Alt+Shift+H) on the active tab.
// Opening it grants `activeTab` for that tab; every action below needs a further click.
// Texts are set with textContent only: nothing from a page, the host or the vault is ever
// parsed as HTML.

import {
  api,
  fillForTab,
  generate,
  listForTab,
  lockVault,
  readLoginForTab,
  saveLogin,
  useGeneratedForTab,
} from './lib/actions.js';
import { messageFor } from './lib/decide.js';

const $ = (id) => document.getElementById(id);

let tab = null;
let origin = null;
/** Login waiting for the user's confirmation; dropped on save or cancel. */
let pending = null;

function show(id, on = true) {
  $(id).hidden = !on;
}

function say(code, alert = true) {
  const m = $('message');
  m.textContent = code === null ? '' : messageFor(code);
  m.classList.toggle('alert', alert);
  m.hidden = code === null;
}

function sayText(text) {
  const m = $('message');
  m.textContent = text;
  m.classList.remove('alert');
  m.hidden = false;
}

function renderEntries(entries) {
  const list = $('entries');
  list.replaceChildren();
  for (const e of entries) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'entry';
    const t = document.createElement('span');
    t.textContent = e.title;
    b.append(t);
    if (e.username) {
      const u = document.createElement('span');
      u.className = 'user';
      u.textContent = e.username;
      b.append(u);
    }
    b.addEventListener('click', async () => {
      b.disabled = true;
      const r = await fillForTab(tab, e);
      b.disabled = false;
      if (r.ok) {
        window.close();
      } else {
        say(r.error);
      }
    });
    li.append(b);
    list.append(li);
  }
}

function openSaveForm(login) {
  pending = { origin: login.origin, password: login.password };
  $('save-title').value = login.title ?? '';
  $('save-username').value = login.username ?? '';
  $('save-origin').textContent = login.origin;
  show('save');
  show('actions', false);
}

function closeSaveForm() {
  pending = null;
  $('save').reset();
  show('save', false);
  show('actions', origin !== null);
}

async function refresh() {
  const r = await listForTab(tab);
  origin = r.origin ?? null;
  show('site', origin !== null);
  $('origin').textContent = origin ?? '';
  if (!r.ok) {
    say(r.error);
    show('logins', false);
    show('actions', false);
    show('lock', r.error !== 'locked' && r.error !== 'no_vault' && origin !== null);
    return;
  }
  say(null);
  show('lock');
  show('actions');
  renderEntries(r.entries);
  show('logins', r.entries.length > 0);
  show('truncated', r.truncated);
  if (r.entries.length === 0) sayText('Aucun identifiant enregistré pour ce site exact.');
}

async function main() {
  const [active] = await api.tabs.query({ active: true, currentWindow: true });
  tab = active ?? null;

  $('propose').addEventListener('click', async () => {
    const r = await readLoginForTab(tab);
    if (!r.ok) return say(r.error);
    openSaveForm(r);
  });

  $('save').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!pending) return;
    const r = await saveLogin(pending.origin, {
      title: $('save-title').value.trim(),
      username: $('save-username').value.trim() || null,
      password: pending.password,
    });
    closeSaveForm();
    if (!r.ok) return say(r.error);
    await refresh();
    sayText('Identifiant enregistré.');
  });
  $('save-cancel').addEventListener('click', closeSaveForm);

  $('gen').addEventListener('click', async () => {
    const length = Number.parseInt($('gen-length').value, 10);
    const r = await generate(Number.isInteger(length) ? length : 20, $('gen-symbols').checked);
    if (!r.ok) return say(r.error);
    $('gen-value').textContent = r.password;
    show('gen-output');
    show('gen-use', origin !== null);
  });

  $('gen-use').addEventListener('click', async () => {
    const password = $('gen-value').textContent;
    const r = await useGeneratedForTab(tab, password);
    if (!r.ok) return say(r.error);
    openSaveForm({ ...r, password });
  });

  $('lock').addEventListener('click', async () => {
    const r = await lockVault();
    if (!r.ok) return say(r.error);
    await refresh();
  });

  await refresh();
}

main().catch(() => say('inject'));
