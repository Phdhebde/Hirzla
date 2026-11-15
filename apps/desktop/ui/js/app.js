// @ts-check
// Screens of the application and their transitions, driven by the core's state.
// The interface polls the core (`Status` does not keep the vault open): when the core locks
// the vault by itself, everything shown is wiped and the unlock screen comes back.

import { api } from "./api.js";
import { announce, byId, showError } from "./dom.js";
import { SecretForm } from "./form.js";
import { applyTheme, loadPrefs } from "./prefs.js";
import { GeneratorView, SettingsView } from "./tools.js";
import { VaultView } from "./vault.js";

/** @typedef {import("./api.js").ApiError} ApiError */
/** @typedef {import("./api.js").Status} Status */

const POLL_MS = 3000;
const prefs = loadPrefs();
applyTheme(prefs.theme);

/** @type {Status | null} */
let status = null;
let userLocked = false;
let pollTimer = 0;

const SCREENS = ["attente", "creation", "deverrouillage", "coffre"];

/** @param {string} name */
function showScreen(name) {
  for (const s of SCREENS) {
    byId(`ecran-${s}`).hidden = s !== name;
  }
  const heading = /** @type {HTMLElement | null} */ (byId(`ecran-${name}`).querySelector("[tabindex='-1']"));
  if (name === "creation") byId("creation-mdp").focus();
  else if (name === "deverrouillage") byId("deverrouillage-mdp").focus();
  else if (name === "coffre") byId("recherche").focus();
  else heading?.focus();
}

function currentScreen() {
  return SCREENS.find((s) => !byId(`ecran-${s}`).hidden) ?? "attente";
}

/**
 * Handles refusals that change the screen. Returns true when handled.
 * @param {ApiError} e
 * @returns {boolean}
 */
function onGlobalError(e) {
  if (e.code === "locked" || e.code === "no_vault") {
    void poll();
    return true;
  }
  if (["core_lost", "core_not_running", "untrusted_core", "unauthorized", "connection"].includes(e.code)) {
    showWaiting(e);
    return true;
  }
  return false;
}

const vault = new VaultView({
  onError: (e) => {
    if (!onGlobalError(e)) announce(e.message, 6000);
  },
  revealSeconds: () => prefs.reveal_s,
  onEdit: (entry) => form.open(entry),
});

const form = new SecretForm({
  onError: onGlobalError,
  onSaved: async (ref) => {
    await vault.refresh();
    if (ref) vault.select(ref.id, false);
  },
});

const generator = new GeneratorView(onGlobalError);
const settings = new SettingsView(prefs, onGlobalError, () => void vault.refresh());

/** Forgets everything the vault showed. */
function wipe() {
  vault.wipe();
  generator.wipe();
  for (const d of document.querySelectorAll("dialog[open]")) {
    /** @type {HTMLDialogElement} */ (d).close();
  }
  form.clear();
  byId("import-resultat").hidden = true;
}

/** @param {ApiError | null} e */
function showWaiting(e) {
  wipe();
  status = null;
  if (e) {
    byId("attente-titre").textContent = "Le noyau ne répond pas";
    byId("attente-texte").hidden = true;
    showError(byId("attente-erreur"), e.message);
    byId("attente-reessayer").hidden = e.code === "core_lost";
  }
  if (currentScreen() !== "attente") showScreen("attente");
}

async function poll() {
  clearTimeout(pollTimer);
  try {
    const s = await api.status();
    const before = status?.state;
    status = s;
    if (s.state === "absent" && currentScreen() !== "creation") {
      wipe();
      showScreen("creation");
    } else if (s.state === "locked" && currentScreen() !== "deverrouillage") {
      wipe();
      if (before === "unlocked" && !userLocked) {
        showError(
          byId("deverrouillage-erreur"),
          `Le coffre a été verrouillé après ${s.auto_lock_s} s d'inactivité.`,
        );
      }
      userLocked = false;
      showScreen("deverrouillage");
    } else if (s.state === "unlocked" && currentScreen() !== "coffre") {
      showError(byId("deverrouillage-erreur"), null);
      showScreen("coffre");
      showView("secrets");
      await vault.refresh();
    }
    if (s.state === "unlocked") settings.render(s);
  } catch (e) {
    const err = /** @type {ApiError} */ (e);
    showWaiting(err);
    if (err.code === "core_lost") return;
  }
  pollTimer = window.setTimeout(() => void poll(), POLL_MS);
}

// --- Creation of the vault -------------------------------------------------------------

byId("form-creation").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = /** @type {HTMLInputElement} */ (byId("creation-mdp"));
  const confirm = /** @type {HTMLInputElement} */ (byId("creation-confirmation"));
  const error = byId("creation-erreur");
  const button = /** @type {HTMLButtonElement} */ (byId("form-creation").querySelector("button[type=submit]"));
  if ([...pw.value].length < 12) {
    showError(error, "Le mot de passe maître doit compter au moins 12 caractères.");
    pw.focus();
    return;
  }
  if (pw.value !== confirm.value) {
    showError(error, "Les deux saisies du mot de passe maître diffèrent.");
    confirm.focus();
    return;
  }
  button.disabled = true;
  button.textContent = "Création du coffre…";
  showError(error, null);
  try {
    await api.createVault(pw.value, confirm.value);
    pw.value = "";
    confirm.value = "";
    announce("Coffre créé. Il est ouvert.");
    await poll();
  } catch (e) {
    const err = /** @type {ApiError} */ (e);
    if (!onGlobalError(err)) showError(error, err.message);
  } finally {
    pw.value = "";
    confirm.value = "";
    button.disabled = false;
    button.textContent = "Créer le coffre";
  }
});

// --- Unlock ----------------------------------------------------------------------------

byId("form-deverrouillage").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = /** @type {HTMLInputElement} */ (byId("deverrouillage-mdp"));
  const error = byId("deverrouillage-erreur");
  const button = /** @type {HTMLButtonElement} */ (byId("form-deverrouillage").querySelector("button[type=submit]"));
  if (!pw.value) {
    showError(error, "Saisissez votre mot de passe maître.");
    pw.focus();
    return;
  }
  button.disabled = true;
  button.textContent = "Ouverture…";
  showError(error, null);
  let wait = 0;
  try {
    await api.unlock(pw.value);
    pw.value = "";
    await poll();
  } catch (e) {
    const err = /** @type {ApiError} */ (e);
    if (err.code === "already_unlocked") {
      await poll();
    } else if (!onGlobalError(err)) {
      showError(error, err.message);
      wait = err.retry_after_s ?? 0;
    }
  } finally {
    pw.value = "";
    button.textContent = "Ouvrir";
    if (wait > 0) {
      const tick = () => {
        if (wait <= 0) {
          button.disabled = false;
          showError(error, null);
          pw.focus();
          return;
        }
        button.textContent = `Ouvrir (${wait} s)`;
        wait -= 1;
        setTimeout(tick, 1000);
      };
      tick();
    } else {
      button.disabled = false;
      pw.focus();
    }
  }
});

// --- Open vault ------------------------------------------------------------------------

/** @param {string} view */
function showView(view) {
  for (const v of ["secrets", "generateur", "reglages"]) {
    byId(`vue-${v}`).hidden = v !== view;
  }
  if (view !== "generateur") generator.wipe();
  if (view === "reglages" && status) settings.render(status);
  if (view === "generateur") void generator.generate();
}

/** @param {string} view @param {string | null} filter */
function markNav(view, filter) {
  for (const b of document.querySelectorAll(".navigation [data-vue]")) {
    const same = b.getAttribute("data-vue") === view && (view !== "secrets" || b.getAttribute("data-filtre") === filter);
    if (same) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
}

byId("ecran-coffre").querySelector(".navigation")?.addEventListener("click", (ev) => {
  const target = /** @type {HTMLElement} */ (ev.target).closest("[data-vue]");
  if (!target) return;
  const view = target.getAttribute("data-vue") ?? "secrets";
  const filter = target.getAttribute("data-filtre");
  showView(view);
  markNav(view, filter);
  if (view === "secrets" && filter) vault.setFilter(filter);
  const heading = /** @type {HTMLElement | null} */ (byId(`vue-${view}`).querySelector("h1"));
  heading?.focus();
});

byId("bouton-nouveau").addEventListener("click", () => form.open(null));

async function lockNow() {
  userLocked = true;
  wipe();
  try {
    await api.lock();
    announce("Coffre verrouillé.");
  } catch (e) {
    onGlobalError(/** @type {ApiError} */ (e));
  }
  await poll();
}
byId("bouton-verrouiller").addEventListener("click", () => void lockNow());

byId("attente-reessayer").addEventListener("click", () => {
  byId("attente-titre").textContent = "Connexion au noyau…";
  byId("attente-texte").hidden = false;
  showError(byId("attente-erreur"), null);
  byId("attente-reessayer").hidden = true;
  void poll();
});

// Keyboard shortcuts of the open vault (Ctrl, or Cmd on macOS).
document.addEventListener("keydown", (ev) => {
  if (currentScreen() !== "coffre" || document.querySelector("dialog[open]")) return;
  if (!(ev.ctrlKey || ev.metaKey) || ev.altKey) return;
  const key = ev.key.toLowerCase();
  if (key === "f") {
    ev.preventDefault();
    showView("secrets");
    byId("recherche").focus();
  } else if (key === "n") {
    ev.preventDefault();
    form.open(null);
  } else if (key === "l") {
    ev.preventDefault();
    void lockNow();
  } else if (key === "g") {
    ev.preventDefault();
    showView("generateur");
    markNav("generateur", null);
    byId("vue-generateur").querySelector("h1")?.focus();
  }
});

// No context menu (it would offer "Inspect" in some web views, and "Copy" of a revealed
// secret outside the delayed clearing).
document.addEventListener("contextmenu", (ev) => {
  const t = /** @type {HTMLElement} */ (ev.target);
  if (!t.closest("input, textarea")) ev.preventDefault();
});

void poll();
