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
  showApp,
  readLoginForTab,
  saveLogin,
  useGeneratedForTab,
} from './lib/actions.js';
import { messageFor } from './lib/decide.js';
import { CONTENT_SCRIPTS, ORIGINS, SCRIPT_IDS } from './lib/passkey.js';

const $ = (id) => document.getElementById(id);

let tab = null;
let origin = null;
/** The vaults of this workstation, when several are registered (ADR 0085); else empty. */
let vaults = [];
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
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.setAttribute('aria-hidden', 'true');
    badge.textContent = (e.title.trim()[0] ?? '?').toUpperCase();
    const names = document.createElement('span');
    names.className = 'names';
    const t = document.createElement('span');
    t.className = 'title';
    t.textContent = e.title;
    names.append(t);
    if (e.username) {
      const u = document.createElement('span');
      u.className = 'user';
      u.textContent = e.username;
      names.append(u);
    }
    // With several vaults, every login says which vault it comes from.
    if (e.alias && vaults.length > 1) {
      const v = document.createElement('span');
      v.className = 'vault';
      v.textContent = `Coffre : ${e.alias}`;
      names.append(v);
    }
    const fill = document.createElement('span');
    fill.className = 'fill';
    fill.textContent = 'Remplir';
    b.append(badge, names, fill);
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

/** The vault's state as the popup knows it: `null` when the core did not answer. */
function showState(open) {
  show('state', open !== null);
  $('state').classList.toggle('open', open === true);
  $('state-text').textContent = open ? 'Ouvert' : 'Verrouillé';
}

/** The open vaults a login may be saved into; the destination vault of the host first. */
function openVaults() {
  return vaults.filter((v) => v.state === 'unlocked').sort((a, b) => Number(b.target) - Number(a.target));
}

function openSaveForm(login) {
  pending = { origin: login.origin, password: login.password };
  $('save-title').value = login.title ?? '';
  $('save-username').value = login.username ?? '';
  $('save-origin').textContent = login.origin;
  // With several vaults the user sees, and may change, where the login goes.
  const choices = vaults.length > 1 ? openVaults() : [];
  $('save-vault').replaceChildren(
    ...choices.map((v) => {
      const o = document.createElement('option');
      o.value = v.vault;
      o.textContent = v.alias;
      return o;
    }),
  );
  show('save-vault-field', choices.length > 0);
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
  vaults = r.vaults ?? [];
  // A locked vault is never asked: it is named, and opened in the application.
  const locked = vaults.length > 1 ? vaults.filter((v) => v.state === 'locked').map((v) => v.alias) : [];
  $('locked-vaults').textContent =
    locked.length === 0
      ? ''
      : `${locked.length === 1 ? 'Coffre verrouillé' : 'Coffres verrouillés'} : ${locked.join(', ')}. ` +
        'Les identifiants d’un coffre verrouillé ne sont pas proposés : ouvrez-le dans l’application.';
  show('locked-vaults', r.ok && locked.length > 0);
  show('site', origin !== null);
  $('origin').textContent = origin ?? '';
  $('site').classList.toggle('verified', r.ok);
  $('site-note').textContent = r.ok ? 'Site vérifié : domaine exact, en https' : '';
  showState(r.ok ? true : r.error === 'locked' ? false : null);
  if (!r.ok) {
    say(r.error);
    show('logins', false);
    show('actions', false);
    show('lock', r.error !== 'locked' && r.error !== 'no_vault' && origin !== null);
    // The application is where the vault is created and unlocked.
    show('open-app', ['locked', 'no_vault', 'unsupported_page'].includes(r.error));
    return;
  }
  say(null);
  show('open-app', locked.length > 0);
  show('lock');
  show('actions');
  renderEntries(r.entries);
  show('logins', r.entries.length > 0);
  show('truncated', r.truncated);
  // The first match takes the focus: Enter fills it, as a click would.
  $('entries').querySelector('button')?.focus();
  if (r.entries.length === 0) sayText('Aucun identifiant enregistré pour ce site exact.');
}

/** Whether the passkey mode is on: permission granted and scripts registered. */
async function passkeysOn() {
  try {
    const granted = await api.permissions.contains({ origins: ORIGINS });
    const scripts = await api.scripting.getRegisteredContentScripts({ ids: SCRIPT_IDS });
    return granted && scripts.length === SCRIPT_IDS.length;
  } catch {
    return false;
  }
}

function showPasskeys(on) {
  $('passkeys-toggle').textContent = on ? 'Désactiver' : 'Activer';
  $('passkeys-state').textContent = on
    ? 'Activées : Hirzla propose ses clés d’accès sur les sites en https.'
    : 'Désactivées : Hirzla ne lit aucune page.';
  show('passkeys-help', !on);
}

async function togglePasskeys() {
  const button = $('passkeys-toggle');
  button.disabled = true;
  try {
    if (await passkeysOn()) {
      await api.scripting.unregisterContentScripts({ ids: SCRIPT_IDS }).catch(() => {});
      await api.permissions.remove({ origins: ORIGINS }).catch(() => {});
    } else {
      await api.scripting.unregisterContentScripts({ ids: SCRIPT_IDS }).catch(() => {});
      await api.scripting.registerContentScripts(CONTENT_SCRIPTS);
    }
  } catch {
    sayText('Les clés d’accès n’ont pas pu être activées.');
  }
  showPasskeys(await passkeysOn());
  button.disabled = false;
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
    const chosen = $('save-vault-field').hidden ? '' : $('save-vault').value;
    const r = await saveLogin(
      pending.origin,
      {
        title: $('save-title').value.trim(),
        username: $('save-username').value.trim() || null,
        password: pending.password,
      },
      chosen ? { vault: chosen } : null,
    );
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

  $('open-app').addEventListener('click', async () => {
    const r = await showApp();
    if (!r.ok) return say(r.error);
    // The window of the application takes the focus; nothing more to do here.
    window.close();
  });

  $('passkeys-toggle').addEventListener('click', () => {
    // The permission is asked first, in the click itself: browsers only show their prompt
    // for a user gesture.
    if ($('passkeys-toggle').textContent === 'Activer') {
      api.permissions
        .request({ origins: ORIGINS })
        .then((granted) => (granted ? togglePasskeys() : showPasskeys(false)))
        .catch(() => showPasskeys(false));
    } else {
      togglePasskeys();
    }
  });
  showPasskeys(await passkeysOn());

  $('lock').addEventListener('click', async () => {
    const r = await lockVault();
    if (!r.ok) return say(r.error);
    await refresh();
  });

  await refresh();
}

main().catch(() => say('inject'));
