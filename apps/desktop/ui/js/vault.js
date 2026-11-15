// @ts-check
// The open vault: lockers, list of secrets, search and the record of one secret.

import { api } from "./api.js";
import { announce, byId, h, mask } from "./dom.js";

/** @typedef {import("./api.js").Entry} Entry */
/** @typedef {import("./api.js").Locker} Locker */
/** @typedef {import("./api.js").FieldName} FieldName */

const TYPE_NAMES = /** @type {Record<string, string>} */ ({
  password: "Mot de passe",
  note: "Note",
  ssh_key: "Clé SSH",
  totp: "Code TOTP",
  passkey: "Clé d'accès",
  file: "Fichier",
  unknown: "Secret",
});

const FIELD_LABELS = /** @type {Record<string, string>} */ ({
  title: "titre",
  username: "identifiant",
  password: "mot de passe",
  notes: "notes",
  favorite: "favori",
  totp: "TOTP",
  ssh_private_key: "clé privée SSH",
  ssh_public_key: "clé publique SSH",
  ssh_passphrase: "phrase de passe",
  passkey: "clé d'accès",
  other: "autre champ",
});

/** Secret fields of a version that may be revealed or copied, with their labels. */
const VERSION_SECRETS = /** @type {[FieldName, string][]} */ ([
  ["password", "Mot de passe"],
  ["notes", "Notes"],
  ["ssh_passphrase", "Phrase de passe"],
]);

/**
 * @typedef {object} VaultHooks
 * @property {(e: import("./api.js").ApiError) => void} onError  Refusal not handled here.
 * @property {() => number} revealSeconds  How long a revealed value stays visible.
 * @property {(entry: Entry) => void} onEdit  Opens the form on this secret.
 */

export class VaultView {
  /** @param {VaultHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    /** @type {Entry[]} */
    this.entries = [];
    /** @type {Locker[]} */
    this.lockers = [];
    /** @type {Entry[]} */
    this.shown = [];
    this.filter = "tous";
    this.query = "";
    /** @type {string | null} */
    this.selectedId = null;
    /** @type {Set<() => void>} Clears revealed values and their timers. */
    this.hiders = new Set();
    this.searchTimer = 0;

    this.list = byId("liste-secrets");
    this.list.addEventListener("keydown", (e) => this.onListKey(e));
    this.list.addEventListener("focus", () => {
      // The keyboard lands on an item, never on an empty list box.
      if (!this.selectedId && this.shown.length > 0) this.select(this.shown[0].id, true);
      this.markActive();
    });
    this.list.addEventListener("blur", () => this.markActive());

    const search = /** @type {HTMLInputElement} */ (byId("recherche"));
    search.addEventListener("input", () => {
      clearTimeout(this.searchTimer);
      this.searchTimer = window.setTimeout(() => {
        this.query = search.value;
        void this.refresh();
      }, 150);
    });
    search.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && search.value) {
        search.value = "";
        this.query = "";
        void this.refresh();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        this.list.focus();
      }
    });

    byId("fiche-modifier").addEventListener("click", () => {
      const entry = this.selected();
      if (entry) this.hooks.onEdit(entry);
    });
    byId("fiche-favori").addEventListener("click", () => void this.toggleFavorite());
    byId("fiche-supprimer").addEventListener("click", () => void this.deleteSelected());
    byId("fiche-restaurer").addEventListener("click", () => void this.restoreSelected());
    byId("fiche-historique").addEventListener("click", () => void this.openHistory());
    byId("dialogue-historique").addEventListener("close", () => {
      this.hideAll();
      byId("historique-liste").replaceChildren();
    });
  }

  /** @returns {Entry | undefined} */
  selected() {
    return this.entries.find((e) => e.id === this.selectedId);
  }

  /** @param {string} filter */
  setFilter(filter) {
    this.filter = filter;
    this.selectedId = null;
    void this.refresh();
  }

  /** Forgets everything shown: called when the vault locks. */
  wipe() {
    this.hideAll();
    this.entries = [];
    this.lockers = [];
    this.shown = [];
    this.selectedId = null;
    this.query = "";
    /** @type {HTMLInputElement} */ (byId("recherche")).value = "";
    this.list.replaceChildren();
    byId("liste-casiers").replaceChildren();
    byId("fiche-champs").replaceChildren();
    byId("fiche-titre").textContent = "";
    byId("fiche-contenu").hidden = true;
    byId("fiche-vide").hidden = false;
  }

  hideAll() {
    for (const hide of [...this.hiders]) hide();
    this.hiders.clear();
  }

  async refresh() {
    try {
      const listing = await api.list(this.query, this.filter === "corbeille");
      this.entries = listing.entries;
      this.lockers = listing.lockers;
    } catch (e) {
      this.hooks.onError(/** @type {any} */ (e));
      return;
    }
    this.renderLockers();
    this.renderList();
  }

  renderLockers() {
    const ul = byId("liste-casiers");
    ul.replaceChildren(
      ...this.lockers.map((l) => {
        const count = this.entries.filter((e) => e.locker === l.id && !e.trash).length;
        const button = h(
          "button",
          { class: "nav-lien", type: "button", "data-vue": "secrets", "data-filtre": `casier:${l.id}` },
          [h("span", { text: l.name }), h("span", { class: "compte", text: String(count), "aria-hidden": "true" })],
        );
        if (this.filter === `casier:${l.id}`) button.setAttribute("aria-current", "page");
        return h("li", {}, [button]);
      }),
    );
  }

  /** @returns {string} */
  filterTitle() {
    if (this.filter === "favoris") return "Favoris";
    if (this.filter === "corbeille") return "Corbeille";
    if (this.filter.startsWith("casier:")) {
      const id = this.filter.slice("casier:".length);
      return this.lockers.find((l) => l.id === id)?.name ?? "Casier";
    }
    return "Tous les secrets";
  }

  renderList() {
    const f = this.filter;
    this.shown = this.entries.filter((e) => {
      if (f === "corbeille") return e.trash;
      if (e.trash) return false;
      if (f === "favoris") return e.favorite;
      if (f.startsWith("casier:")) return e.locker === f.slice("casier:".length);
      return true;
    });
    byId("liste-titre").textContent = this.filterTitle();
    const n = this.shown.length;
    byId("liste-compte").textContent = n === 0 ? "" : n === 1 ? "1 secret" : `${n} secrets`;
    const empty = byId("liste-vide");
    if (n === 0) {
      empty.textContent = this.query
        ? "Aucun secret ne correspond à cette recherche."
        : f === "corbeille"
          ? "La corbeille est vide."
          : f === "favoris"
            ? "Aucun favori. Marquez un secret comme favori depuis sa fiche."
            : "Aucun secret. Créez-en un, ou importez un fichier depuis les réglages.";
    }
    empty.hidden = n !== 0;
    this.list.hidden = n === 0;
    this.list.replaceChildren(
      ...this.shown.map((e) =>
        h(
          "li",
          { id: `opt-${e.id}`, class: "element", role: "option", "aria-selected": e.id === this.selectedId ? "true" : "false" },
          [
            h("span", { class: "element-pastille", "aria-hidden": "true", text: initial(e.title) }),
            h("span", { class: "element-titre", text: e.title }),
            e.favorite ? h("span", { class: "element-favori", text: "★", title: "Favori" }) : h("span"),
            h("span", { class: "element-sous", text: subtitle(e) }),
          ],
        ),
      ),
    );
    for (const li of this.list.children) {
      li.addEventListener("click", () => this.select(li.id.slice(4), false));
    }
    if (this.selectedId && !this.shown.some((e) => e.id === this.selectedId)) {
      this.selectedId = null;
    }
    this.markActive();
    this.renderRecord();
  }

  markActive() {
    const focused = document.activeElement === this.list;
    for (const li of this.list.children) {
      li.classList.toggle("actif", focused && li.id === `opt-${this.selectedId}`);
    }
    if (this.selectedId) this.list.setAttribute("aria-activedescendant", `opt-${this.selectedId}`);
    else this.list.removeAttribute("aria-activedescendant");
  }

  /**
   * @param {string} id
   * @param {boolean} keepFocus
   */
  select(id, keepFocus) {
    if (id === this.selectedId) return;
    this.selectedId = id;
    for (const li of this.list.children) {
      li.setAttribute("aria-selected", li.id === `opt-${id}` ? "true" : "false");
    }
    if (!keepFocus) this.list.focus();
    this.markActive();
    document.getElementById(`opt-${id}`)?.scrollIntoView({ block: "nearest" });
    this.renderRecord();
  }

  /** @param {KeyboardEvent} e */
  onListKey(e) {
    if (this.shown.length === 0) return;
    const i = this.shown.findIndex((x) => x.id === this.selectedId);
    let next = -1;
    if (e.key === "ArrowDown") next = i < 0 ? 0 : Math.min(i + 1, this.shown.length - 1);
    else if (e.key === "ArrowUp") next = i < 0 ? 0 : Math.max(i - 1, 0);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = this.shown.length - 1;
    else if (e.key === "Enter" && i >= 0) {
      e.preventDefault();
      byId("fiche-titre").focus();
      return;
    } else return;
    e.preventDefault();
    this.select(this.shown[next].id, true);
  }

  renderRecord() {
    this.hideAll();
    const entry = this.selected();
    byId("fiche-vide").hidden = !!entry;
    byId("fiche-contenu").hidden = !entry;
    const fields = byId("fiche-champs");
    fields.replaceChildren();
    if (!entry) return;
    byId("fiche-type").textContent = TYPE_NAMES[entry.kind] ?? TYPE_NAMES.unknown;
    byId("fiche-titre").textContent = entry.title;
    const fav = byId("fiche-favori");
    fav.setAttribute("aria-pressed", entry.favorite ? "true" : "false");
    fav.textContent = entry.favorite ? "Favori" : "Ajouter aux favoris";
    fav.hidden = entry.trash;
    byId("fiche-modifier").hidden = entry.trash || !["password", "note"].includes(entry.kind);
    byId("fiche-supprimer").textContent = entry.trash ? "Supprimer définitivement" : "Mettre à la corbeille";
    byId("fiche-restaurer").hidden = !entry.trash;

    const ref = { locker: entry.locker, id: entry.id };
    if (entry.trash) {
      fields.append(info("État", "Dans la corbeille. Restaurez-le pour le retrouver dans la liste."));
    }
    if (entry.kind === "password") {
      if (entry.username) fields.append(this.plainField("Identifiant", entry.username, ref, "username"));
      fields.append(this.secretField("Mot de passe", ref, "password"));
      if (entry.hosts.length) fields.append(listField("Sites", entry.hosts, "mono"));
      if (entry.tags.length) fields.append(listField("Étiquettes", entry.tags, "etiquette"));
      fields.append(this.secretField("Notes", ref, "notes"));
    } else if (entry.kind === "note") {
      if (entry.tags.length) fields.append(listField("Étiquettes", entry.tags, "etiquette"));
      fields.append(this.secretField("Contenu", ref, "notes"));
    } else if (entry.kind === "ssh_key") {
      fields.append(this.secretField("Clé publique", ref, "ssh_public_key"));
      fields.append(this.secretField("Phrase de passe", ref, "ssh_passphrase"));
    } else {
      fields.append(info("Contenu", "Ce type de secret s'affichera dans une prochaine version de l'application."));
    }
  }

  /**
   * A field from the index (user name): shown, with a copy button.
   * @param {string} label
   * @param {string} value
   * @param {import("./api.js").SecretRef} ref
   * @param {FieldName} field
   */
  plainField(label, value, ref, field) {
    const copy = h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: "Copier" });
    copy.setAttribute("aria-label", `Copier : ${label.toLowerCase()}`);
    copy.addEventListener("click", () => void this.copy(ref, field, label));
    return h("div", { class: "champ-fiche" }, [
      h("dt", { text: label }),
      h("dd", { class: "valeur-secrete", text: value }),
      h("dd", { class: "actions-champ" }, [copy]),
    ]);
  }

  /**
   * A secret field: masked; revealed on request for a few seconds; copied without being
   * shown.
   * @param {string} label
   * @param {import("./api.js").SecretRef} ref
   * @param {FieldName} field
   */
  secretField(label, ref, field) {
    const value = h("span", { class: "valeur-secrete valeur-masquee", text: mask() });
    const countdown = h("span", { class: "decompte", "aria-live": "polite" });
    const shape = h("span", { class: "etat etat-scelle" }, [
      h("span", { class: "forme forme-carre", "aria-hidden": "true" }),
      "Scellé",
    ]);
    const reveal = /** @type {HTMLButtonElement} */ (
      h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: "Révéler", "aria-pressed": "false" })
    );
    reveal.setAttribute("aria-label", `Révéler : ${label.toLowerCase()}`);
    const copy = /** @type {HTMLButtonElement} */ (
      h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: "Copier" })
    );
    copy.setAttribute("aria-label", `Copier : ${label.toLowerCase()}`);

    let timer = 0;
    let left = 0;
    const hide = () => {
      clearInterval(timer);
      timer = 0;
      value.textContent = mask();
      value.classList.add("valeur-masquee");
      countdown.textContent = "";
      reveal.textContent = "Révéler";
      reveal.setAttribute("aria-pressed", "false");
      shape.className = "etat etat-scelle";
      shape.replaceChildren(h("span", { class: "forme forme-carre", "aria-hidden": "true" }), "Scellé");
      this.hiders.delete(hide);
    };
    reveal.addEventListener("click", async () => {
      if (timer) {
        hide();
        return;
      }
      let text;
      try {
        text = await api.reveal(ref, field);
      } catch (e) {
        const err = /** @type {import("./api.js").ApiError} */ (e);
        if (err.code === "not_found") {
          value.textContent = "Vide";
          value.classList.add("valeur-masquee");
          reveal.disabled = true;
          copy.disabled = true;
          return;
        }
        this.hooks.onError(err);
        return;
      }
      value.textContent = text;
      text = "";
      value.classList.remove("valeur-masquee");
      reveal.textContent = "Masquer";
      reveal.setAttribute("aria-pressed", "true");
      shape.className = "etat etat-ouvert";
      shape.replaceChildren(h("span", { class: "forme forme-rond", "aria-hidden": "true" }), "Descellé");
      left = this.hooks.revealSeconds();
      countdown.textContent = `Masqué dans ${left} s`;
      this.hiders.add(hide);
      timer = window.setInterval(() => {
        left -= 1;
        if (left <= 0) hide();
        else countdown.textContent = `Masqué dans ${left} s`;
      }, 1000);
    });
    copy.addEventListener("click", () => void this.copy(ref, field, label));
    return h("div", { class: "champ-fiche" }, [
      h("dt", {}, [h("span", { class: "libelle-champ", text: label }), shape]),
      h("dd", {}, [value, countdown]),
      h("dd", { class: "actions-champ" }, [reveal, copy]),
    ]);
  }

  /**
   * @param {import("./api.js").SecretRef} ref
   * @param {FieldName} field
   * @param {string} label
   */
  async copy(ref, field, label) {
    try {
      const s = await api.copyField(ref, field);
      announce(`${label} copié. Le presse-papiers sera effacé dans ${s} s.`);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "not_found") announce(`${label} : aucune valeur.`);
      else this.hooks.onError(err);
    }
  }

  async toggleFavorite() {
    const entry = this.selected();
    if (!entry) return;
    try {
      await api.update({ locker: entry.locker, id: entry.id }, { favorite: !entry.favorite });
      announce(entry.favorite ? "Retiré des favoris." : "Ajouté aux favoris.");
      await this.refresh();
    } catch (e) {
      this.hooks.onError(/** @type {any} */ (e));
    }
  }

  async restoreSelected() {
    const entry = this.selected();
    if (!entry || !entry.trash) return;
    try {
      await api.restore({ locker: entry.locker, id: entry.id });
      announce(`« ${entry.title} » est sorti de la corbeille.`);
      this.selectedId = null;
      await this.refresh();
      this.list.focus();
    } catch (e) {
      this.hooks.onError(/** @type {any} */ (e));
    }
  }

  /** Shows the versions of the selected secret. */
  async openHistory() {
    const entry = this.selected();
    if (!entry) return;
    const ref = { locker: entry.locker, id: entry.id };
    /** @type {import("./api.js").Version[]} */
    let versions;
    try {
      versions = await api.history(ref);
    } catch (e) {
      this.hooks.onError(/** @type {any} */ (e));
      return;
    }
    byId("historique-titre").textContent = `Historique de « ${entry.title} »`;
    const n = versions.length;
    byId("historique-liste").replaceChildren(
      ...versions.map((v, i) => this.versionItem(ref, v, n - i, i === 0)),
    );
    const dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-historique"));
    if (!dialog.open) dialog.showModal();
  }

  /**
   * One version in the history dialog.
   * @param {import("./api.js").SecretRef} ref
   * @param {import("./api.js").Version} v
   * @param {number} number  1 for the oldest.
   * @param {boolean} current
   */
  versionItem(ref, v, number, current) {
    const when = v.wall_ms > 0 ? new Date(v.wall_ms).toLocaleString("fr-FR") : "date inconnue";
    const state = v.state === "trash" ? " · dans la corbeille" : v.state === "purged" ? " · supprimé" : "";
    const changed = v.changed.length ? v.changed.map((f) => FIELD_LABELS[f] ?? f).join(", ") : "état";
    const value = h("span", { class: "valeur-secrete" });
    /** @type {HTMLElement[]} */
    const actions = [];
    for (const [field, label] of VERSION_SECRETS) {
      if (!v.fields.includes(field)) continue;
      const reveal = h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: `Révéler ${label.toLowerCase()}` });
      reveal.addEventListener("click", () => void this.revealVersion(ref, v.version, field, label, value));
      const copy = h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: `Copier ${label.toLowerCase()}` });
      copy.addEventListener("click", () => void this.copyVersion(ref, v.version, field, label));
      actions.push(reveal, copy);
    }
    if (!current && v.state !== "purged") {
      const restore = h("button", { class: "bouton bouton-principal bouton-petit", type: "button", text: "Rétablir cette version" });
      restore.addEventListener("click", () => void this.restoreVersion(ref, v, number));
      actions.push(restore);
    }
    return h("li", { class: "version" }, [
      h("p", { class: "version-titre", text: `Version ${number}${current ? " (actuelle)" : ""} · ${when}${state}` }),
      h("p", { text: `${v.title}${v.username ? ` · ${v.username}` : ""}` }),
      h("p", { class: "texte-secondaire", text: `Modifié : ${changed}` }),
      value,
      h("div", { class: "actions-champ" }, actions),
    ]);
  }

  /**
   * @param {import("./api.js").SecretRef} ref
   * @param {string} version
   * @param {FieldName} field
   * @param {string} label
   * @param {HTMLElement} out
   */
  async revealVersion(ref, version, field, label, out) {
    this.hideAll();
    let text;
    try {
      text = await api.revealVersion(ref, version, field);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "not_found") announce(`${label} : aucune valeur dans cette version.`);
      else this.hooks.onError(err);
      return;
    }
    out.textContent = `${label} : ${text}`;
    text = "";
    const hide = () => {
      clearTimeout(timer);
      out.textContent = "";
      this.hiders.delete(hide);
    };
    const timer = window.setTimeout(hide, this.hooks.revealSeconds() * 1000);
    this.hiders.add(hide);
  }

  /**
   * @param {import("./api.js").SecretRef} ref
   * @param {string} version
   * @param {FieldName} field
   * @param {string} label
   */
  async copyVersion(ref, version, field, label) {
    try {
      const s = await api.copyVersion(ref, version, field);
      announce(`${label} copié. Le presse-papiers sera effacé dans ${s} s.`);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "not_found") announce(`${label} : aucune valeur dans cette version.`);
      else this.hooks.onError(err);
    }
  }

  /**
   * @param {import("./api.js").SecretRef} ref
   * @param {import("./api.js").Version} v
   * @param {number} number
   */
  async restoreVersion(ref, v, number) {
    const history = /** @type {HTMLDialogElement} */ (byId("dialogue-historique"));
    history.close();
    const ok = await confirmDialog(
      `Rétablir la version ${number} ?`,
      "Ses valeurs redeviennent l'état actuel du secret. La version actuelle reste dans l'historique.",
      "Rétablir",
    );
    if (!ok) return;
    try {
      await api.restoreVersion(ref, v.version);
      announce(`Version ${number} rétablie.`);
      await this.refresh();
      await this.openHistory();
    } catch (e) {
      this.hooks.onError(/** @type {any} */ (e));
    }
  }

  async deleteSelected() {
    const entry = this.selected();
    if (!entry) return;
    const purge = entry.trash;
    const ok = await confirmDialog(
      purge ? "Supprimer définitivement ?" : "Mettre à la corbeille ?",
      purge
        ? `« ${entry.title} » sera supprimé définitivement. Cette action ne peut pas être annulée.`
        : `« ${entry.title} » ira dans la corbeille.`,
      purge ? "Supprimer" : "Mettre à la corbeille",
    );
    if (!ok) return;
    try {
      await api.remove({ locker: entry.locker, id: entry.id }, purge);
      announce(purge ? "Secret supprimé définitivement." : "Secret mis à la corbeille.");
      this.selectedId = null;
      await this.refresh();
      this.list.focus();
    } catch (e) {
      this.hooks.onError(/** @type {any} */ (e));
    }
  }
}

/** @param {string} title */
function initial(title) {
  const c = title.trim().charAt(0);
  return c ? c.toLocaleUpperCase("fr") : "?";
}

/** @param {Entry} e */
function subtitle(e) {
  if (e.kind === "password") return e.username || e.hosts[0] || TYPE_NAMES.password;
  return TYPE_NAMES[e.kind] ?? TYPE_NAMES.unknown;
}

/**
 * @param {string} label
 * @param {string} text
 */
function info(label, text) {
  return h("div", { class: "champ-fiche" }, [h("dt", { text: label }), h("dd", { text })]);
}

/**
 * @param {string} label
 * @param {string[]} items
 * @param {string} cls
 */
function listField(label, items, cls) {
  return h("div", { class: "champ-fiche" }, [
    h("dt", { text: label }),
    h("dd", {}, items.map((t) => h("span", { class: cls === "etiquette" ? "etiquette" : "mono etiquette", text: t }))),
  ]);
}

/**
 * Asks for confirmation in a modal dialog.
 * @param {string} title
 * @param {string} text
 * @param {string} yes
 * @returns {Promise<boolean>}
 */
export function confirmDialog(title, text, yes) {
  const dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-confirmation"));
  byId("confirmation-titre").textContent = title;
  byId("confirmation-texte").textContent = text;
  byId("confirmation-oui").textContent = yes;
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "oui"), { once: true });
  });
}
