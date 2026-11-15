// @ts-check
// Creating and changing a secret. The form never loads an existing password or note: to
// change one, the user types or generates a new value; left empty, it stays as it is.

import { api } from "./api.js";
import { announce, byId, showError } from "./dom.js";

/** @typedef {import("./api.js").Entry} Entry */

/**
 * @typedef {object} FormHooks
 * @property {(e: import("./api.js").ApiError) => boolean} onError  True when handled globally.
 * @property {(ref: import("./api.js").SecretRef | null) => void} onSaved
 */

export class SecretForm {
  /** @param {FormHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-secret"));
    this.form = /** @type {HTMLFormElement} */ (byId("form-secret"));
    /** @type {Entry | null} */
    this.editing = null;
    this.title = /** @type {HTMLInputElement} */ (byId("secret-titre"));
    this.username = /** @type {HTMLInputElement} */ (byId("secret-identifiant"));
    this.password = /** @type {HTMLInputElement} */ (byId("secret-mdp"));
    this.urls = /** @type {HTMLTextAreaElement} */ (byId("secret-urls"));
    this.tags = /** @type {HTMLInputElement} */ (byId("secret-etiquettes"));
    this.notes = /** @type {HTMLTextAreaElement} */ (byId("secret-notes"));
    this.favorite = /** @type {HTMLInputElement} */ (byId("secret-favori"));
    this.error = byId("secret-erreur");
    this.saving = false;

    this.form.addEventListener("submit", (e) => {
      e.preventDefault();
      void this.save();
    });
    this.form.addEventListener("change", (e) => {
      if (/** @type {HTMLElement} */ (e.target).getAttribute("name") === "secret-type") this.syncType();
    });
    for (const b of this.form.querySelectorAll("[data-fermer]")) {
      b.addEventListener("click", () => this.dialog.close());
    }
    this.dialog.addEventListener("close", () => this.clear());
    const show = byId("secret-mdp-voir");
    show.addEventListener("click", () => {
      const visible = this.password.type === "text";
      this.password.type = visible ? "password" : "text";
      show.textContent = visible ? "Afficher" : "Masquer";
      show.setAttribute("aria-pressed", visible ? "false" : "true");
    });
    byId("secret-mdp-generer").addEventListener("click", () => void this.generate());
  }

  /** @returns {"password" | "note"} */
  kind() {
    const checked = /** @type {HTMLInputElement | null} */ (
      this.form.querySelector('input[name="secret-type"]:checked')
    );
    return checked?.value === "note" ? "note" : "password";
  }

  syncType() {
    const isNote = this.kind() === "note";
    for (const el of this.form.querySelectorAll("[data-pour='password']")) {
      /** @type {HTMLElement} */ (el).hidden = isNote;
    }
    for (const el of this.form.querySelectorAll("[data-creation]")) {
      const hide = !!this.editing || (isNote && el.getAttribute("data-pour") === "password");
      /** @type {HTMLElement} */ (el).hidden = hide;
    }
  }

  /** @param {Entry | null} entry  null: a new secret. */
  open(entry) {
    this.clear();
    this.editing = entry;
    byId("dialogue-secret-titre").textContent = entry ? "Modifier le secret" : "Nouveau secret";
    byId("secret-type-groupe").hidden = !!entry;
    byId("secret-mdp-aide").hidden = !entry;
    byId("secret-notes-aide").hidden = !entry;
    const kind = entry?.kind === "note" ? "note" : "password";
    for (const r of this.form.querySelectorAll('input[name="secret-type"]')) {
      /** @type {HTMLInputElement} */ (r).checked = /** @type {HTMLInputElement} */ (r).value === kind;
    }
    if (entry) {
      this.title.value = entry.title;
      this.username.value = entry.username ?? "";
      this.favorite.checked = entry.favorite;
    }
    this.syncType();
    this.dialog.showModal();
    this.title.focus();
  }

  /** Empties every input, so that no typed secret stays in the page. */
  clear() {
    for (const el of [this.title, this.username, this.password, this.urls, this.tags, this.notes]) {
      el.value = "";
    }
    this.password.type = "password";
    byId("secret-mdp-voir").textContent = "Afficher";
    byId("secret-mdp-voir").setAttribute("aria-pressed", "false");
    this.favorite.checked = false;
    showError(this.error, null);
  }

  async generate() {
    try {
      this.password.value = await api.generate({ length: 24, lower: true, upper: true, digits: true, symbols: true });
      announce("Mot de passe généré.");
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(this.error, err.message);
    }
  }

  async save() {
    if (this.saving) return;
    const title = this.title.value.trim();
    if (!title) {
      showError(this.error, "Le titre est obligatoire.");
      this.title.focus();
      return;
    }
    this.saving = true;
    byId("secret-enregistrer").setAttribute("disabled", "");
    try {
      let ref = null;
      if (this.editing) {
        /** @type {Record<string, unknown>} */
        const changes = {};
        /** @type {string[]} */
        const clear = [];
        const e = this.editing;
        if (title !== e.title) changes.title = title;
        if (e.kind === "password") {
          const u = this.username.value;
          if (u !== (e.username ?? "")) {
            if (u) changes.username = u;
            else clear.push("username");
          }
          if (this.password.value) changes.password = this.password.value;
        }
        if (this.notes.value) changes.notes = this.notes.value;
        if (this.favorite.checked !== e.favorite) changes.favorite = this.favorite.checked;
        if (clear.length) changes.clear = clear;
        if (Object.keys(changes).length === 0) {
          this.dialog.close();
          return;
        }
        await api.update({ locker: e.locker, id: e.id }, changes);
        ref = { locker: e.locker, id: e.id };
        announce("Secret modifié.");
      } else {
        const kind = this.kind();
        /** @type {Record<string, unknown>} */
        const secret = {
          kind,
          locker: null,
          title,
          notes: this.notes.value || null,
          tags: this.tags.value.split(",").map((t) => t.trim()).filter(Boolean),
          favorite: this.favorite.checked,
        };
        if (kind === "password") {
          secret.username = this.username.value || null;
          secret.password = this.password.value || null;
          secret.urls = this.urls.value.split("\n").map((u) => u.trim()).filter(Boolean);
        }
        ref = await api.create(secret);
        announce("Secret créé.");
      }
      this.dialog.close();
      this.hooks.onSaved(ref);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(this.error, err.message);
    } finally {
      this.saving = false;
      byId("secret-enregistrer").removeAttribute("disabled");
    }
  }
}
