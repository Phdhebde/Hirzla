// @ts-check
// Generator, settings and import.

import { api } from "./api.js";
import { announce, byId, h, showError } from "./dom.js";
import { applyTheme, savePrefs } from "./prefs.js";

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
};

/** @param {number} s */
function duration(s) {
  if (s % 60 === 0 && s >= 60) {
    const m = s / 60;
    return m === 1 ? "1 minute" : `${m} minutes`;
  }
  return `${s} secondes`;
}

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
    byId("import-kdbx").addEventListener("click", () => {
      /** @type {HTMLDialogElement} */ (byId("dialogue-kdbx")).showModal();
    });
  }

  /** @param {import("./api.js").Status} s */
  render(s) {
    byId("reglage-auto").textContent = `après ${duration(s.auto_lock_s)} d'inactivité`;
    byId("reglage-pp").textContent = `après ${duration(s.clipboard_clear_s || 30)}`;
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
