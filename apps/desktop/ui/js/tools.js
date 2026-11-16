// @ts-check
// Generator, settings (display, vault, master password, recovery kit) and import.

import { api } from "./api.js";
import { announce, byId, h, showError } from "./dom.js";
import { applyTheme, savePrefs } from "./prefs.js";
import { confirmDialog } from "./vault.js";

/** @typedef {import("./prefs.js").Prefs} Prefs */

export class GeneratorView {
  /** @param {(e: import("./api.js").ApiError) => boolean} onError  True when handled globally. */
  constructor(onError) {
    this.onError = onError;
    this.output = byId("generateur-resultat");
    this.copyButton = /** @type {HTMLButtonElement} */ (byId("generateur-copier"));
    this.length = /** @type {HTMLInputElement} */ (byId("generateur-longueur"));
    this.error = byId("generateur-erreur");
    this.length.addEventListener("input", () => {
      byId("generateur-longueur-valeur").textContent = this.length.value;
    });
    this.length.addEventListener("change", () => void this.generate());
    for (const id of ["generateur-minuscules", "generateur-majuscules", "generateur-chiffres", "generateur-symboles"]) {
      byId(id).addEventListener("change", () => void this.generate());
    }
    byId("form-generateur").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.generate();
    });
    this.copyButton.addEventListener("click", () => void this.copy());
  }

  /** @param {string} id */
  checked(id) {
    return /** @type {HTMLInputElement} */ (byId(id)).checked;
  }

  async generate() {
    showError(this.error, null);
    try {
      const value = await api.generate({
        length: Number(this.length.value),
        lower: this.checked("generateur-minuscules"),
        upper: this.checked("generateur-majuscules"),
        digits: this.checked("generateur-chiffres"),
        symbols: this.checked("generateur-symboles"),
      });
      this.output.textContent = value;
      this.copyButton.disabled = false;
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      this.wipe();
      if (!this.onError(err)) showError(this.error, err.message);
    }
  }

  async copy() {
    try {
      const s = await api.copyGenerated();
      announce(`Mot de passe copié. Le presse-papiers sera effacé dans ${s} s.`);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.onError(err)) showError(this.error, err.message);
    }
  }

  wipe() {
    this.output.textContent = "";
    this.copyButton.disabled = true;
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

  /** Reads the vault's settings and recovery kit: when the settings view opens. */
  async load() {
    showError(byId("reglages-coffre-erreur"), null);
    showError(byId("recouvrement-erreur"), null);
    try {
      const s = await api.getSettings();
      /** @type {HTMLInputElement} */ (byId("reglage-auto")).value = String(s.auto_lock_s);
      /** @type {HTMLInputElement} */ (byId("reglage-pp")).value = String(s.clipboard_clear_s);
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
    if (!Number.isInteger(settings.auto_lock_s) || !Number.isInteger(settings.clipboard_clear_s)) {
      showError(error, "Les délais s'expriment en secondes entières.");
      return;
    }
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
