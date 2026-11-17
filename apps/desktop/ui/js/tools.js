// @ts-check
// Generator, settings (display, vault, master password, recovery kit) and import.

import { api } from "./api.js";
import { announce, byId, h, icon, showError } from "./dom.js";
import { applyTheme, savePrefs } from "./prefs.js";
import { confirmDialog } from "./vault.js";

/** @typedef {import("./prefs.js").Prefs} Prefs */

/** @typedef {import("./api.js").GeneratorSpec} GeneratorSpec */
/** @typedef {GeneratorSpec["mode"]} GeneratorMode */

/** Names of the built-in profiles, by identifier of the core. */
/** @type {Record<string, string>} */
const PROFILE_NAMES = {
  defaut: "Par défaut",
  "longue-duree": "Longue durée, 256 bits",
  "site-capricieux": "Site capricieux",
  wifi: "Wi-Fi, sans ambiguïté",
  "compte-de-service": "Compte de service",
};

/** Entropy aimed at when no profile is selected, and upper end of the gauge, in bits. */
const DEFAULT_TARGET = 128;
const GAUGE_MAX = 256;

const FAMILIES = /** @type {const} */ (["minuscules", "majuscules", "chiffres", "symboles"]);

/** @param {number} millibits */
function bits(millibits) {
  return Math.floor(millibits / 1000);
}

export class GeneratorView {
  /**
   * @param {(e: import("./api.js").ApiError) => boolean} onError  True when handled globally.
   * @param {(value: string) => void} onCreate  Opens a new secret with this password.
   */
  constructor(onError, onCreate) {
    this.onError = onError;
    this.output = byId("generateur-resultat");
    this.copyButton = /** @type {HTMLButtonElement} */ (byId("generateur-copier"));
    this.createButton = /** @type {HTMLButtonElement} */ (byId("generateur-creer"));
    this.batch = byId("generateur-lot-liste");
    this.error = byId("generateur-erreur");
    /** @type {GeneratorMode} */
    this.mode = "characters";
    /** @type {import("./api.js").GeneratorProfile[] | null} */
    this.profiles = null;
    /** @type {string | null} */
    this.profile = null;
    this.target = DEFAULT_TARGET;
    /** Last single value: shown already, kept to prefill a new secret. */
    this.value = "";

    const form = byId("form-generateur");
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      void this.generate(1);
    });
    // Any setting changed by hand leaves the profile and draws again.
    form.addEventListener("change", (e) => {
      if (!(e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement)) return;
      this.syncLength(e.target);
      this.selectProfile(null);
      void this.generate(1);
    });
    form.addEventListener("input", (e) => {
      if (e.target instanceof HTMLInputElement) this.syncLength(e.target);
    });
    for (const b of byId("generateur-modes").querySelectorAll("button")) {
      b.addEventListener("click", () => {
        this.setMode(/** @type {GeneratorMode} */ (b.dataset.mode));
        this.selectProfile(null);
        void this.generate(1);
      });
    }
    this.copyButton.addEventListener("click", () => void this.copy(0));
    this.createButton.addEventListener("click", () => {
      if (this.value) onCreate(this.value);
    });
    byId("generateur-lot").addEventListener("click", () => void this.generate(10));
  }

  /** Keeps the length slider and its number field together. @param {HTMLElement} source */
  syncLength(source) {
    const range = this.input("generateur-longueur");
    const number = this.input("generateur-longueur-nombre");
    if (source === range) number.value = range.value;
    if (source === number) range.value = number.value;
  }

  /** @param {string} id */
  input(id) {
    return /** @type {HTMLInputElement} */ (byId(id));
  }

  /** @param {string} id */
  checked(id) {
    return this.input(id).checked;
  }

  /** @param {string} id */
  number(id) {
    return Number(this.input(id).value);
  }

  /** @param {GeneratorMode} mode */
  setMode(mode) {
    this.mode = mode;
    for (const b of byId("generateur-modes").querySelectorAll("button")) {
      b.setAttribute("aria-pressed", String(b.dataset.mode === mode));
    }
    for (const panel of document.querySelectorAll("[data-mode-panneau]")) {
      /** @type {HTMLElement} */ (panel).hidden = panel.getAttribute("data-mode-panneau") !== mode;
    }
  }

  /** @param {string | null} id */
  selectProfile(id) {
    this.profile = id;
    this.target = this.profiles?.find((p) => p.id === id)?.target_bits ?? DEFAULT_TARGET;
    for (const b of byId("generateur-profils").querySelectorAll("button")) {
      b.setAttribute("aria-pressed", String(b.dataset.profil === id));
    }
  }

  /** The settings of the form, as the application expects them. @returns {GeneratorSpec} */
  spec() {
    switch (this.mode) {
      case "passphrase":
        return {
          mode: "passphrase",
          words: this.number("generateur-mots"),
          separator: /** @type {HTMLSelectElement} */ (byId("generateur-separateur")).value,
          capitalize: this.checked("generateur-mots-majuscule"),
          digits: this.number("generateur-mots-chiffres"),
        };
      case "pronounceable":
        return {
          mode: "pronounceable",
          syllables: this.number("generateur-syllabes"),
          capitalize: this.checked("generateur-syllabes-majuscule"),
          digits: this.number("generateur-syllabes-chiffres"),
          no_ambiguous: this.checked("generateur-syllabes-sans-ambigus"),
        };
      case "pin":
        return {
          mode: "pin",
          length: this.number("generateur-pin"),
          no_repeat: this.checked("generateur-pin-sans-repetition"),
          no_sequence: this.checked("generateur-pin-sans-suite"),
        };
      case "template":
        return {
          mode: "template",
          template: this.input("generateur-modele").value,
          symbol_set: this.input("generateur-modele-jeu").value || null,
          excluded: this.input("generateur-modele-exclus").value,
          no_ambiguous: this.checked("generateur-modele-sans-ambigus"),
          same_keys: this.checked("generateur-modele-memes-touches"),
          no_repeat: this.checked("generateur-modele-sans-repetition"),
        };
      default: {
        const on = FAMILIES.map((f) => this.checked(`generateur-${f}`));
        return {
          mode: "characters",
          length: this.number("generateur-longueur-nombre"),
          lower: on[0],
          upper: on[1],
          digits: on[2],
          symbols: on[3],
          // A family left out asks for nothing, whatever its field still shows.
          minimums: /** @type {[number, number, number, number]} */ (
            FAMILIES.map((f, i) => (on[i] ? this.number(`generateur-${f}-min`) : 0))
          ),
          symbol_set: this.input("generateur-jeu").value || null,
          excluded: this.input("generateur-exclus").value,
          no_ambiguous: this.checked("generateur-sans-ambigus"),
          same_keys: this.checked("generateur-memes-touches"),
          no_repeat: this.checked("generateur-sans-repetition"),
          start_letter: this.checked("generateur-debut-lettre"),
        };
      }
    }
  }

  /** Copies a profile's settings into the form. @param {GeneratorSpec} spec */
  fill(spec) {
    this.setMode(spec.mode);
    if (spec.mode !== "characters") return;
    this.input("generateur-longueur").value = String(spec.length);
    this.input("generateur-longueur-nombre").value = String(spec.length);
    const on = [spec.lower, spec.upper, spec.digits, spec.symbols];
    FAMILIES.forEach((f, i) => {
      this.input(`generateur-${f}`).checked = on[i];
      this.input(`generateur-${f}-min`).value = String(spec.minimums[i]);
    });
    this.input("generateur-jeu").value = spec.symbol_set ?? "";
    this.input("generateur-exclus").value = spec.excluded;
    this.input("generateur-sans-ambigus").checked = spec.no_ambiguous;
    this.input("generateur-memes-touches").checked = spec.same_keys;
    this.input("generateur-sans-repetition").checked = spec.no_repeat;
    this.input("generateur-debut-lettre").checked = spec.start_letter;
  }

  /** Loads the profiles once, then draws: when the view opens. */
  async open() {
    if (!this.profiles) {
      try {
        this.profiles = await api.generatorProfiles();
      } catch (e) {
        const err = /** @type {import("./api.js").ApiError} */ (e);
        if (!this.onError(err)) showError(this.error, err.message);
        return;
      }
      byId("generateur-profils").replaceChildren(
        ...this.profiles.map((p) => {
          const b = h("button", {
            class: "pastille",
            type: "button",
            "data-profil": p.id,
            "aria-pressed": "false",
            text: PROFILE_NAMES[p.id] ?? p.id,
          });
          b.addEventListener("click", () => {
            this.fill(p.spec);
            this.selectProfile(p.id);
            void this.generate(1);
          });
          return b;
        }),
      );
      const first = this.profiles[0];
      if (first) {
        this.fill(first.spec);
        this.selectProfile(first.id);
      }
    }
    await this.generate(1);
  }

  /** A value with its digits and symbols told apart by more than their shape. @param {string} value */
  colored(value) {
    return [...value].map((c) => {
      const cls = /[0-9]/.test(c) ? "car-chiffre" : /[\p{L}\s]/u.test(c) ? "" : "car-symbole";
      return cls ? h("span", { class: cls, text: c }) : document.createTextNode(c);
    });
  }

  /** @param {number} count  1, or a batch. */
  async generate(count) {
    showError(this.error, null);
    try {
      const r = await api.generateWith(this.spec(), count);
      this.value = r.values[0] ?? "";
      this.output.replaceChildren(...this.colored(this.value));
      this.copyButton.disabled = false;
      this.createButton.disabled = false;
      this.batch.hidden = count === 1;
      this.batch.replaceChildren(
        ...(count === 1
          ? []
          : r.values.map((v, i) => {
              const copy = h("button", { class: "bouton bouton-icone bouton-discret", type: "button", "aria-label": `Copier la valeur ${i + 1}` }, [
                icon("copier"),
              ]);
              copy.addEventListener("click", () => void this.copy(i));
              return h("li", {}, [h("span", { class: "valeur-secrete" }, this.colored(v)), copy]);
            })),
      );
      this.showStrength(r.strength);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      this.wipe();
      if (!this.onError(err)) showError(this.error, err.message);
    }
  }

  /** @param {{ entropy_millibits: number, pool: number }} s */
  showStrength(s) {
    const n = bits(s.entropy_millibits);
    const gauge = /** @type {HTMLProgressElement} */ (byId("generateur-jauge"));
    gauge.value = Math.min(n, GAUGE_MAX);
    gauge.classList.toggle("jauge-faible", n < this.target);
    byId("generateur-cible").style.setProperty("left", `${(Math.min(this.target, GAUGE_MAX) / GAUGE_MAX) * 100}%`);
    byId("generateur-cible-texte").textContent = this.profile
      ? `Objectif du profil : ${this.target} bits`
      : `Repère : ${this.target} bits`;
    byId("generateur-bits").textContent = `${n} bits`;
    byId("generateur-classique").textContent = `${n} bits`;
    byId("generateur-quantique").textContent = `environ ${Math.floor(n / 2)} bits`;
    const spec = this.spec();
    /** @type {string} */
    let draw;
    switch (spec.mode) {
      case "characters":
        draw = `${s.pool} caractères, ${spec.length} positions`;
        break;
      case "passphrase":
        draw = `${s.pool} mots, ${spec.words} tirés`;
        break;
      case "pronounceable":
        draw = `${s.pool} syllabes, ${spec.syllables} tirées`;
        break;
      case "pin":
        draw = `${s.pool} chiffres, ${spec.length} positions`;
        break;
      default:
        draw = "selon chaque position du modèle";
    }
    byId("generateur-tirage").textContent = draw;
  }

  /** @param {number} index */
  async copy(index) {
    try {
      const s = await api.copyGeneratedAt(index);
      announce(`Valeur copiée. Le presse-papiers sera effacé dans ${s} s.`);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.onError(err)) showError(this.error, err.message);
    }
  }

  /** Forgets every generated value shown: called when the view closes or the vault locks. */
  wipe() {
    this.value = "";
    this.output.replaceChildren();
    this.batch.replaceChildren();
    this.batch.hidden = true;
    this.copyButton.disabled = true;
    this.createButton.disabled = true;
    for (const id of ["generateur-bits", "generateur-classique", "generateur-quantique", "generateur-tirage"]) {
      byId(id).textContent = "";
    }
    /** @type {HTMLProgressElement} */ (byId("generateur-jauge")).value = 0;
  }
}

/** @type {Record<string, string>} */
const HARDENING = {
  applied: "Appliquée",
  partial: "Partielle",
  unsupported: "Impossible sur ce système",
  failed: "Échec",
  not_attempted: "Non tentée (moteur web)",
};

export class SettingsView {
  /**
   * @param {Prefs} prefs
   * @param {(e: import("./api.js").ApiError) => boolean} onError
   * @param {() => void} onImported
   */
  constructor(prefs, onError, onImported) {
    this.prefs = prefs;
    this.onError = onError;
    this.onImported = onImported;
    for (const r of document.querySelectorAll('input[name="theme"]')) {
      const radio = /** @type {HTMLInputElement} */ (r);
      radio.checked = radio.value === prefs.theme;
      radio.addEventListener("change", () => {
        if (!radio.checked) return;
        prefs.theme = /** @type {Prefs["theme"]} */ (radio.value);
        applyTheme(prefs.theme);
        savePrefs(prefs);
      });
    }
    const reveal = /** @type {HTMLSelectElement} */ (byId("reglage-revelation"));
    reveal.value = String(prefs.reveal_s);
    reveal.addEventListener("change", () => {
      prefs.reveal_s = Number(reveal.value);
      savePrefs(prefs);
    });
    byId("import-csv").addEventListener("click", () => void this.importCsv());
    byId("import-kdbx").addEventListener("click", () => this.openKdbx());
    byId("kdbx-choisir").addEventListener("click", () => void this.chooseKdbx());
    byId("form-kdbx").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.importKdbx();
    });
    byId("dialogue-kdbx").addEventListener("close", () => {
      /** @type {HTMLInputElement} */ (byId("kdbx-mdp")).value = "";
    });
    byId("reglage-zone").addEventListener("change", () => void this.saveTray());
    byId("form-reglages-coffre").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.saveVaultSettings();
    });
    byId("form-mdp").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.changePassword();
    });
    byId("form-recouvrement").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.createKit();
    });
    byId("recouvrement-retirer").addEventListener("click", () => void this.removeKit());
    /** @type {import("./api.js").RecoveryKit | null} */
    this.kit = null;
  }

  /** @param {import("./api.js").LocalPreferences} p */
  renderTray(p) {
    const box = /** @type {HTMLInputElement} */ (byId("reglage-zone"));
    box.checked = p.keep_in_tray && p.tray_available;
    box.disabled = !p.tray_available;
    byId("reglage-zone-aide").hidden = !p.tray_available;
    byId("reglage-zone-absente").hidden = p.tray_available;
  }

  /** The notification area preference applies at once: it belongs to this workstation. */
  async saveTray() {
    const error = byId("reglages-poste-erreur");
    const box = /** @type {HTMLInputElement} */ (byId("reglage-zone"));
    showError(error, null);
    try {
      this.renderTray(await api.setPreferences(box.checked));
      announce(box.checked ? "Hirzla reste dans la zone de notification." : "Fermer la fenêtre arrêtera Hirzla.");
    } catch (e) {
      box.checked = !box.checked;
      showError(error, /** @type {import("./api.js").ApiError} */ (e).message);
    }
  }

  /** Reads the vault's settings and recovery kit: when the settings view opens. */
  async load() {
    showError(byId("reglages-coffre-erreur"), null);
    showError(byId("recouvrement-erreur"), null);
    showError(byId("reglages-poste-erreur"), null);
    try {
      this.renderTray(await api.getPreferences());
      const s = await api.getSettings();
      this.choose("reglage-auto", s.auto_lock_s);
      this.choose("reglage-pp", s.clipboard_clear_s);
      /** @type {HTMLInputElement} */ (byId("reglage-veille")).checked = s.lock_on_sleep;
      /** @type {HTMLInputElement} */ (byId("reglage-session")).checked = s.lock_on_session_lock;
      this.renderKit(await api.recoveryStatus());
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.onError(err)) showError(byId("reglages-coffre-erreur"), err.message);
    }
  }

  /** Forgets what the settings view holds: called when the vault locks. */
  wipe() {
    for (const id of ["mdp-actuel", "mdp-nouveau", "mdp-confirmation", "kdbx-mdp"]) {
      /** @type {HTMLInputElement} */ (byId(id)).value = "";
    }
    byId("recouvrement-resultat").hidden = true;
    byId("kdbx-fichier").textContent = "";
    /** @type {HTMLButtonElement} */ (byId("kdbx-importer")).disabled = true;
  }

  /**
   * Selects a delay in a list of durations. A value set elsewhere (CLI, older version) that
   * the list does not offer is added as is, so saving the form never changes it silently.
   * @param {string} id
   * @param {number} seconds
   */
  choose(id, seconds) {
    const select = /** @type {HTMLSelectElement} */ (byId(id));
    const value = String(seconds);
    if (![...select.options].some((o) => o.value === value)) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = seconds === 0 ? "Délai par défaut du noyau" : `${seconds} secondes`;
      select.append(option);
    }
    select.value = value;
  }

  /** @param {string} id */
  number(id) {
    return Number(/** @type {HTMLInputElement} */ (byId(id)).value);
  }

  async saveVaultSettings() {
    const error = byId("reglages-coffre-erreur");
    showError(error, null);
    const settings = {
      auto_lock_s: this.number("reglage-auto"),
      clipboard_clear_s: this.number("reglage-pp"),
      lock_on_sleep: /** @type {HTMLInputElement} */ (byId("reglage-veille")).checked,
      lock_on_session_lock: /** @type {HTMLInputElement} */ (byId("reglage-session")).checked,
    };
    try {
      await api.setSettings(settings);
      announce("Réglages du coffre enregistrés.");
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.onError(err)) showError(error, err.message);
    }
  }

  async changePassword() {
    const current = /** @type {HTMLInputElement} */ (byId("mdp-actuel"));
    const next = /** @type {HTMLInputElement} */ (byId("mdp-nouveau"));
    const confirm = /** @type {HTMLInputElement} */ (byId("mdp-confirmation"));
    const error = byId("mdp-erreur");
    const button = /** @type {HTMLButtonElement} */ (byId("form-mdp").querySelector("button[type=submit]"));
    showError(error, null);
    if (!current.value) {
      showError(error, "Saisissez votre mot de passe actuel.");
      current.focus();
      return;
    }
    if ([...next.value].length < 12) {
      showError(error, "Le mot de passe maître doit compter au moins 12 caractères.");
      next.focus();
      return;
    }
    if (next.value !== confirm.value) {
      showError(error, "Les deux saisies du mot de passe maître diffèrent.");
      confirm.focus();
      return;
    }
    button.disabled = true;
    button.textContent = "Changement…";
    try {
      await api.changePassword(current.value, next.value, confirm.value);
      announce("Mot de passe maître changé.");
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.onError(err)) showError(error, err.message);
    } finally {
      current.value = "";
      next.value = "";
      confirm.value = "";
      button.disabled = false;
      button.textContent = "Changer le mot de passe";
    }
  }

  /** @param {import("./api.js").RecoveryKit | null} kit */
  renderKit(kit) {
    this.kit = kit;
    byId("recouvrement-etat").textContent = kit
      ? `Kit ${kit.kit} en place : ${kit.threshold} parts sur ${kit.count} rouvrent le coffre.`
      : "Aucun kit de recouvrement : sans le mot de passe maître, le coffre ne peut pas être rouvert.";
    byId("recouvrement-retirer").hidden = !kit;
    byId("recouvrement-creer").textContent = kit ? "Remplacer le kit…" : "Créer le kit…";
  }

  async createKit() {
    const error = byId("recouvrement-erreur");
    const box = byId("recouvrement-resultat");
    showError(error, null);
    box.hidden = true;
    const count = this.number("recouvrement-parts");
    const threshold = this.number("recouvrement-seuil");
    if (!Number.isInteger(count) || !Number.isInteger(threshold) || threshold < 2 || threshold > count || count > 16) {
      showError(error, "Un kit compte de 2 à 16 parts, et il en faut au moins 2 pour rouvrir le coffre.");
      return;
    }
    if (this.kit) {
      const ok = await confirmDialog(
        "Remplacer le kit de recouvrement ?",
        `Les parts du kit ${this.kit.kit} n'ouvriront plus le coffre.`,
        "Remplacer",
      );
      if (!ok) return;
    }
    try {
      const made = await api.createRecoveryKit(threshold, count);
      box.replaceChildren(
        h("p", { text: `Kit ${made.kit} créé : ${made.threshold} parts sur ${made.count} rouvrent le coffre.` }),
        h("p", { text: `Parts écrites dans ${made.folder} :` }),
        h("ul", { class: "liste-puces mono" }, made.files.map((f) => h("li", { text: f }))),
        h("p", {
          text: "Remettez chaque part à une personne différente (clé USB, coffre papier…), puis effacez-les de ce dossier.",
        }),
      );
      box.hidden = false;
      this.renderKit({ kit: made.kit, threshold: made.threshold, count: made.count });
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "cancelled") return;
      if (!this.onError(err)) showError(error, err.message);
      // A kit may have been made before a share failed to be written.
      try {
        this.renderKit(await api.recoveryStatus());
      } catch {
        // Already reported.
      }
    }
  }

  async removeKit() {
    if (!this.kit) return;
    const ok = await confirmDialog(
      "Retirer le kit de recouvrement ?",
      `Les parts du kit ${this.kit.kit} n'ouvriront plus le coffre.`,
      "Retirer le kit",
    );
    if (!ok) return;
    try {
      await api.removeRecoveryKit();
      byId("recouvrement-resultat").hidden = true;
      this.renderKit(null);
      announce("Kit de recouvrement retiré.");
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.onError(err)) showError(byId("recouvrement-erreur"), err.message);
    }
  }

  openKdbx() {
    showError(byId("kdbx-erreur"), null);
    byId("kdbx-fichier").textContent = "";
    /** @type {HTMLButtonElement} */ (byId("kdbx-importer")).disabled = true;
    /** @type {HTMLDialogElement} */ (byId("dialogue-kdbx")).showModal();
    byId("kdbx-choisir").focus();
  }

  async chooseKdbx() {
    showError(byId("kdbx-erreur"), null);
    try {
      const name = await api.chooseKdbxFile();
      byId("kdbx-fichier").textContent = name;
      /** @type {HTMLButtonElement} */ (byId("kdbx-importer")).disabled = false;
      byId("kdbx-mdp").focus();
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "cancelled") return;
      if (!this.onError(err)) showError(byId("kdbx-erreur"), err.message);
    }
  }

  async importKdbx() {
    const pw = /** @type {HTMLInputElement} */ (byId("kdbx-mdp"));
    const button = /** @type {HTMLButtonElement} */ (byId("kdbx-importer"));
    const error = byId("kdbx-erreur");
    showError(error, null);
    button.disabled = true;
    button.textContent = "Import…";
    try {
      const r = await api.importKdbx(pw.value);
      pw.value = "";
      /** @type {HTMLDialogElement} */ (byId("dialogue-kdbx")).close();
      /** @type {string[]} */
      const lines = [
        r.imported === 0 ? "Aucun secret importé." : r.imported === 1 ? "1 secret importé." : `${r.imported} secrets importés.`,
      ];
      /** @type {[number, string][]} */
      const notes = [
        [r.empty, "entrée(s) vide(s) ignorée(s) (ni mot de passe ni notes)."],
        [r.recycled, "entrée(s) de la corbeille KeePass ignorée(s)."],
        [r.refused, "entrée(s) refusée(s) par le coffre (valeur trop longue ou non permise)."],
        [r.attachments, "pièce(s) jointe(s) non importée(s)."],
        [r.history, "version(s) antérieure(s) d'entrées non importée(s)."],
        [r.custom_skipped, "champ(s) personnalisé(s) au-delà des limites du coffre, non importé(s)."],
        [r.totp, "configuration(s) TOTP non importée(s) : ce type arrive dans une prochaine version."],
      ];
      for (const [n, text] of notes) if (n) lines.push(`${n} ${text}`);
      const box = byId("import-resultat");
      box.replaceChildren(...lines.map((t) => h("p", { text: t })));
      box.hidden = false;
      this.onImported();
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      pw.value = "";
      if (!this.onError(err)) {
        showError(error, err.message);
        pw.focus();
      }
    } finally {
      button.disabled = !byId("kdbx-fichier").textContent;
      button.textContent = "Importer";
    }
  }

  /** @param {import("./api.js").Status} s */
  render(s) {
    byId("reglage-version").textContent = s.core_version;
    byId("reglage-version-app").textContent = s.app_version;
    /** @type {[string, keyof import("./api.js").Hardening][]} */
    const rows = [
      ["Mémoire hors fichier d'échange", "memory_locked"],
      ["Vidages mémoire interdits", "dumps_disabled"],
      ["Traçage interdit", "tracing_blocked"],
    ];
    byId("reglage-durcissement").replaceChildren(
      ...rows.map(([label, key]) =>
        h("tr", {}, [
          h("th", { scope: "row", text: label }),
          h("td", { text: HARDENING[s.core_hardening[key]] ?? "?" }),
          h("td", { text: s.app_hardening ? (HARDENING[s.app_hardening[key]] ?? "?") : "Non encore appliquée" }),
        ]),
      ),
    );
  }

  async importCsv() {
    const box = byId("import-resultat");
    box.hidden = true;
    const button = /** @type {HTMLButtonElement} */ (byId("import-csv"));
    button.disabled = true;
    try {
      const r = await api.importCsv();
      /** @type {string[]} */
      const lines = [
        r.imported === 0 ? "Aucun secret importé." : r.imported === 1 ? "1 secret importé." : `${r.imported} secrets importés.`,
      ];
      if (r.empty) lines.push(`${r.empty} ligne(s) sans mot de passe ni note, ignorée(s).`);
      if (r.refused_lines.length) {
        const shown = r.refused_lines.slice(0, 20).join(", ");
        const more = r.refused_lines.length > 20 ? "…" : "";
        lines.push(`Refusées par le noyau (valeur trop longue ou non permise) : lignes ${shown}${more}.`);
      }
      if (r.totp_skipped) lines.push(`${r.totp_skipped} code(s) TOTP non importé(s) : ce type arrive dans une prochaine version.`);
      lines.push("Pensez à supprimer le fichier CSV : il contient vos mots de passe en clair.");
      box.replaceChildren(...lines.map((t) => h("p", { text: t })));
      box.hidden = false;
      this.onImported();
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "cancelled") return;
      if (!this.onError(err)) {
        box.replaceChildren(h("p", { text: err.message }));
        box.hidden = false;
      }
    } finally {
      button.disabled = false;
    }
  }
}
