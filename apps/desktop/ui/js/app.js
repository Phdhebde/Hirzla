// @ts-check
// Screens of the application and their transitions, driven by the core's state.
// The interface polls the core (`Status` does not keep the vault open): when the core locks
// the vault by itself, everything shown is wiped and the unlock screen comes back.

import { api } from "./api.js";
import { announce, byId, h, showError } from "./dom.js";
import { SecretForm } from "./form.js";
import { Palette } from "./palette.js";
import { applyTheme, loadPrefs } from "./prefs.js";
import { ROLE_NAMES, ServerView, WRITING_ROLES } from "./server.js";
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
  onEdit: (entry) => void form.open(entry),
  onMembers: (locker, name) => void server.members.open(locker, name),
  onFilter: (filter) => markNav("secrets", filter),
});

const form = new SecretForm({
  onError: onGlobalError,
  onSaved: async (ref) => {
    await vault.refresh();
    if (ref) vault.select(ref.id, false);
  },
});

const server = new ServerView({
  prefs,
  onError: onGlobalError,
  onChanged: () => vault.refresh(),
  onStatus: (s) => {
    /** @type {Map<string, import("./vault.js").SharedInfo>} */
    const shared = new Map();
    for (const l of s?.lockers ?? []) {
      shared.set(l.id, {
        role: l.role ? ROLE_NAMES[l.role] : null,
        access: l.access,
        writes: l.access && !l.frozen && !!l.role && WRITING_ROLES.includes(l.role),
      });
    }
    vault.setShared(shared);
  },
  onShow: () => {
    showView("serveur");
    markNav("serveur", null);
    byId("vue-serveur").querySelector("h1")?.focus();
  },
});

/** Opens the form for a new secret, in the locker shown if the member may write there. */
function newSecret() {
  form.setLockers(
    vault.lockers.filter((l) => {
      if (l.personal) return true;
      const s = server.locker(l.id);
      return !!s && s.access && !!s.role && WRITING_ROLES.includes(s.role);
    }),
  );
  void form.open(null, vault.lockerFilter());
}

const generator = new GeneratorView(onGlobalError, (value) => {
  void form.open(null, vault.lockerFilter()).then(() => {
    form.password.value = value;
  });
});

/** Shows a view of the open vault and marks it in the navigation. @param {string} view */
function goTo(view) {
  showView(view);
  markNav(view, view === "secrets" ? "tous" : null);
  byId(`vue-${view}`).querySelector("h1")?.focus();
}

const palette = new Palette({
  onError: onGlobalError,
  iconOf: (kind) => VaultView.iconOf(kind),
  onOpen: (entry) => {
    showView("secrets");
    markNav("secrets", "tous");
    void vault.reveal(entry);
  },
  actions: () => [
    { label: "Nouveau secret", icon: "plus", keys: "Ctrl N", run: () => newSecret() },
    { label: "Générateur de mots de passe", icon: "generateur", keys: "Ctrl G", run: () => goTo("generateur") },
    { label: "Serveur", icon: "serveur", run: () => goTo("serveur") },
    { label: "Réglages", icon: "reglages", run: () => goTo("reglages") },
    { label: "Verrouiller le coffre", icon: "verrou", keys: "Ctrl L", run: () => void lockNow() },
  ],
});
byId("bouton-palette").addEventListener("click", () => palette.open());
const settings = new SettingsView(prefs, onGlobalError, () => void vault.refresh());

/** Forgets everything the vault showed. */
function wipe() {
  vault.wipe();
  palette.close();
  generator.wipe();
  for (const d of document.querySelectorAll("dialog[open]")) {
    /** @type {HTMLDialogElement} */ (d).close();
  }
  form.clear();
  settings.wipe();
  server.wipe();
  wipeRecovery();
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
          "Le coffre a été verrouillé : inactivité, mise en veille ou verrouillage de la session.",
        );
      }
      userLocked = false;
      showScreen("deverrouillage");
      void offerRecovery();
    } else if (s.state === "unlocked" && currentScreen() !== "coffre") {
      showError(byId("deverrouillage-erreur"), null);
      showScreen("coffre");
      showView("secrets");
      await vault.refresh();
      await server.refresh();
    }
    if (s.state === "unlocked") {
      settings.render(s);
      byId("etat-coffre-texte").textContent = `Ouvert · verrouillage après ${duration(s.auto_lock_s)}`;
    }
  } catch (e) {
    const err = /** @type {ApiError} */ (e);
    showWaiting(err);
    if (err.code === "core_lost") return;
  }
  pollTimer = window.setTimeout(() => void poll(), POLL_MS);
}

/**
 * A delay in plain words: « 30 s », « 5 min », « 1 h 30 ».
 * @param {number} seconds
 * @returns {string}
 */
function duration(seconds) {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const rest = minutes % 60;
  return rest ? `${Math.floor(minutes / 60)} h ${rest}` : `${minutes / 60} h`;
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

// Show or hide the master password while typing, and warn about Caps Lock.
{
  const pw = /** @type {HTMLInputElement} */ (byId("deverrouillage-mdp"));
  const see = byId("deverrouillage-voir");
  const mask = () => {
    pw.type = "password";
    see.setAttribute("aria-pressed", "false");
    see.setAttribute("aria-label", "Afficher le mot de passe maître");
  };
  see.addEventListener("click", () => {
    if (pw.type === "password") {
      pw.type = "text";
      see.setAttribute("aria-pressed", "true");
      see.setAttribute("aria-label", "Masquer le mot de passe maître");
    } else mask();
    pw.focus();
  });
  byId("form-deverrouillage").addEventListener("submit", mask);
  /** @param {KeyboardEvent} ev */
  const caps = (ev) => {
    if (typeof ev.getModifierState === "function") {
      byId("deverrouillage-majuscules").hidden = !ev.getModifierState("CapsLock");
    }
  };
  pw.addEventListener("keydown", caps);
  pw.addEventListener("keyup", caps);
  pw.addEventListener("blur", () => {
    byId("deverrouillage-majuscules").hidden = true;
  });
}

// --- Recovery kit (ADR 0034) -----------------------------------------------------------

/** Shows the recovery link on the unlock screen when the vault has a kit. */
async function offerRecovery() {
  const link = byId("lien-recouvrement");
  try {
    const kit = await api.recoveryStatus();
    link.hidden = !kit;
    if (kit) {
      byId("recouvrement-ouvrir-texte").textContent =
        `Réunissez ${kit.threshold} des ${kit.count} parts du kit ${kit.kit}, puis choisissez un nouveau mot de ` +
        "passe maître : il remplacera l'ancien.";
    }
  } catch {
    link.hidden = true;
  }
}

function wipeRecovery() {
  for (const id of ["recouvrement-mdp", "recouvrement-confirmation"]) {
    /** @type {HTMLInputElement} */ (byId(id)).value = "";
  }
  byId("recouvrement-fichiers").replaceChildren();
  /** @type {HTMLButtonElement} */ (byId("recouvrement-ouvrir")).disabled = true;
}

byId("lien-recouvrement").addEventListener("click", () => {
  wipeRecovery();
  showError(byId("recouvrement-ouvrir-erreur"), null);
  /** @type {HTMLDialogElement} */ (byId("dialogue-recouvrement")).showModal();
  byId("recouvrement-choisir").focus();
});
byId("dialogue-recouvrement").addEventListener("close", wipeRecovery);

byId("recouvrement-choisir").addEventListener("click", async () => {
  const error = byId("recouvrement-ouvrir-erreur");
  showError(error, null);
  try {
    const names = await api.chooseRecoveryShares();
    byId("recouvrement-fichiers").replaceChildren(...names.map((n) => h("li", { text: n })));
    /** @type {HTMLButtonElement} */ (byId("recouvrement-ouvrir")).disabled = false;
    byId("recouvrement-mdp").focus();
  } catch (e) {
    const err = /** @type {ApiError} */ (e);
    if (err.code !== "cancelled" && !onGlobalError(err)) showError(error, err.message);
  }
});

byId("form-recouvrement-ouvrir").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = /** @type {HTMLInputElement} */ (byId("recouvrement-mdp"));
  const confirm = /** @type {HTMLInputElement} */ (byId("recouvrement-confirmation"));
  const error = byId("recouvrement-ouvrir-erreur");
  const button = /** @type {HTMLButtonElement} */ (byId("recouvrement-ouvrir"));
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
  button.textContent = "Ouverture…";
  showError(error, null);
  try {
    await api.recoveryUnlock(pw.value, confirm.value);
    /** @type {HTMLDialogElement} */ (byId("dialogue-recouvrement")).close();
    announce("Coffre ouvert avec le kit de recouvrement. Votre nouveau mot de passe maître est en place.", 8000);
    await poll();
  } catch (e) {
    const err = /** @type {ApiError} */ (e);
    if (!onGlobalError(err)) showError(error, err.message);
  } finally {
    pw.value = "";
    confirm.value = "";
    button.textContent = "Ouvrir le coffre";
    button.disabled = byId("recouvrement-fichiers").childElementCount === 0;
  }
});

// Buttons that close their dialog without submitting it.
document.addEventListener("click", (ev) => {
  const b = /** @type {HTMLElement} */ (ev.target).closest("[data-fermer]");
  const dialog = b?.closest("dialog");
  if (dialog && dialog.open) dialog.close();
});

// --- Open vault ------------------------------------------------------------------------

/** @param {string} view */
function showView(view) {
  for (const v of ["secrets", "generateur", "serveur", "reglages"]) {
    byId(`vue-${v}`).hidden = v !== view;
  }
  if (view === "serveur") {
    void server.refresh();
    void server.loadIdentity();
  }
  if (view !== "generateur") generator.wipe();
  if (view === "reglages" && status) settings.render(status);
  if (view === "reglages") void settings.load();
  if (view === "generateur") void generator.open();
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

byId("bouton-nouveau").addEventListener("click", () => newSecret());

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
  if (key === "k") {
    ev.preventDefault();
    palette.open();
  } else if (key === "f") {
    ev.preventDefault();
    showView("secrets");
    byId("recherche").focus();
  } else if (key === "n") {
    ev.preventDefault();
    newSecret();
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
