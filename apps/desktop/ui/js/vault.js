// @ts-check
// The open vault: lockers, list of secrets, search and the record of one secret.

import { api } from "./api.js";
import { announce, byId, h, icon, mask } from "./dom.js";
import { FolderDialog, Trees } from "./folders.js";

/** @typedef {import("./api.js").Entry} Entry */
/** @typedef {import("./api.js").Locker} Locker */
/** @typedef {import("./api.js").FieldName} FieldName */

const TYPE_NAMES = /** @type {Record<string, string>} */ ({
  password: "Mot de passe",
  note: "Note",
  ssh_key: "Clé SSH",
  ssh_connection: "Connexion SSH",
  rdp_connection: "Connexion RDP",
  totp: "Code TOTP",
  passkey: "Clé d'accès",
  file: "Fichier",
  unknown: "Secret",
});

/** Icon of each type of secret (sprite of index.html). */
const TYPE_ICONS = /** @type {Record<string, string>} */ ({
  password: "identifiant",
  note: "note",
  ssh_key: "cle",
  ssh_connection: "terminal",
  rdp_connection: "ecran",
  totp: "totp",
  passkey: "cle",
  file: "fichier",
  unknown: "secret",
});

/** Types that have their own filter in the navigation, with the kinds each one gathers. */
const TYPE_FILTERS = /** @type {Record<string, string[]>} */ ({
  password: ["password", "totp"],
  ssh_key: ["ssh_key"],
  connexion: ["ssh_connection", "rdp_connection"],
  note: ["note"],
});

/** What a link of a connection says when its target is not usable. */
const LINK_STATES = /** @type {Record<string, string>} */ ({
  broken: "Lien rompu : la cible est absente de ce poste",
  trashed: "Cible à la corbeille",
  wrong_type: "Lien refusé : la cible n'est pas du type attendu",
  loop: "Chaîne de rebonds trop longue ou qui boucle",
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
 * @property {(e: import("./api.js").ApiError) => boolean} handles  Refusals that change the screen.
 * @property {() => number} revealSeconds  How long a revealed value stays visible.
 * @property {(entry: Entry) => void} onEdit  Opens the form on this secret.
 * @property {(locker: string, name: string) => void} onMembers  Opens the members of a shared locker.
 * @property {(filter: string) => void} onFilter  The view changed its filter by itself.
 * @property {import("./autotype.js").AutoType} autoType  Typing into another application.
 */

/**
 * What the server mode says of a shared locker, ready to show.
 * @typedef {{ role: string | null, access: boolean, writes: boolean }} SharedInfo
 */

export class VaultView {
  /** @param {VaultHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    /** @type {Entry[]} */
    this.entries = [];
    /** @type {Locker[]} */
    this.lockers = [];
    /** @type {Map<string, SharedInfo>} Shared lockers, by identifier (server mode). */
    this.shared = new Map();
    /** Folders of each locker (ADR 0076). */
    this.trees = new Trees();
    /** @type {Set<string>} Lockers and folders folded in the navigation. */
    this.folded = new Set();
    this.folderDialog = new FolderDialog(hooks.handles);
    /** @type {Entry[]} */
    this.shown = [];
    this.filter = "tous";
    this.query = "";
    /** @type {string | null} */
    this.selectedId = null;
    /** @type {Set<() => void>} Clears revealed values and their timers. */
    this.hiders = new Set();
    /** @type {Set<() => void>} Stops the TOTP codes of the record shown and clears them. */
    this.tickers = new Set();
    this.searchTimer = 0;
    /** Number of the record being drawn: a record read from the core is dropped when it is no longer the one shown. */
    this.recordToken = 0;

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
    byId("fiche-deplacer").addEventListener("click", () => this.moveSelected());
    byId("dossier-nouveau").addEventListener("click", () => this.newFolder());
    byId("dossier-renommer").addEventListener("click", () => this.renameFolder());
    byId("dossier-deplacer").addEventListener("click", () => this.moveFolder());
    byId("dossier-supprimer").addEventListener("click", () => void this.deleteFolder());
    // The menu of the record closes once an action is chosen, or on Escape.
    const menu = /** @type {HTMLDetailsElement} */ (byId("fiche-menu"));
    menu.addEventListener("click", (e) => {
      if (/** @type {HTMLElement} */ (e.target).closest(".menu-action")) menu.open = false;
    });
    menu.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && menu.open) {
        e.stopPropagation();
        menu.open = false;
        menu.querySelector("summary")?.focus();
      }
    });
    document.addEventListener("click", (e) => {
      if (menu.open && !menu.contains(/** @type {Node} */ (e.target))) menu.open = false;
    });
    byId("liste-membres").addEventListener("click", () => {
      const id = this.lockerFilter();
      const locker = this.lockers.find((l) => l.id === id);
      if (locker) this.hooks.onMembers(locker.id, locker.name);
    });
    byId("dialogue-historique").addEventListener("close", () => {
      this.hideAll();
      byId("historique-liste").replaceChildren();
    });
  }

  /** @returns {Entry | undefined} */
  selected() {
    return this.entries.find((e) => e.id === this.selectedId);
  }

  /** The locker shown alone, or the locker of the folder shown, if any. @returns {string | null} */
  lockerFilter() {
    if (this.filter.startsWith("casier:")) return this.filter.slice("casier:".length);
    return this.folderFilter()?.locker ?? null;
  }

  /** The folder shown, if any (`dossier:LOCKER:FOLDER`). @returns {{ locker: string, folder: string } | null} */
  folderFilter() {
    if (!this.filter.startsWith("dossier:")) return null;
    const [locker, folder] = this.filter.slice("dossier:".length).split(":");
    return locker && folder ? { locker, folder } : null;
  }

  /** Whether this device may write in a locker. @param {string} locker @returns {boolean} */
  writes(locker) {
    const l = this.lockers.find((x) => x.id === locker);
    if (!l) return false;
    if (l.personal) return true;
    const info = this.shared.get(locker);
    return !!info && info.access && info.writes;
  }

  /**
   * New state of the shared lockers (server mode).
   * @param {Map<string, SharedInfo>} shared
   */
  setShared(shared) {
    this.shared = shared;
    if (this.lockers.length > 0) {
      this.renderLockers();
      this.renderLockerHeader();
    }
  }

  /** Icon name of a type of secret. @param {string} kind @returns {string} */
  static iconOf(kind) {
    return TYPE_ICONS[kind] ?? TYPE_ICONS.unknown;
  }

  /**
   * Shows the record of a secret from anywhere (quick access): back to the whole vault, no
   * search, this secret selected.
   * @param {Entry} entry
   */
  async reveal(entry) {
    this.filter = "tous";
    this.query = "";
    /** @type {HTMLInputElement} */ (byId("recherche")).value = "";
    this.selectedId = null;
    await this.refresh();
    if (this.shown.some((e) => e.id === entry.id)) {
      this.select(entry.id, true);
      byId("fiche-titre").focus();
    }
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
    this.stopTickers();
    this.entries = [];
    this.lockers = [];
    this.shared = new Map();
    this.trees.clear();
    this.shown = [];
    this.selectedId = null;
    this.query = "";
    /** @type {HTMLInputElement} */ (byId("recherche")).value = "";
    this.list.replaceChildren();
    byId("liste-casiers").replaceChildren();
    byId("liste-casier-partage").hidden = true;
    byId("liste-dossier").hidden = true;
    byId("fiche-champs").replaceChildren();
    byId("fiche-principales").replaceChildren();
    byId("fiche-icone").replaceChildren();
    for (const id of ["compte-tous", "compte-favoris", ...Object.keys(TYPE_FILTERS).map((t) => `compte-${t}`)]) {
      byId(id).textContent = "";
    }
    byId("fiche-titre").textContent = "";
    byId("fiche-contenu").hidden = true;
    byId("fiche-vide").hidden = false;
  }

  hideAll() {
    for (const hide of [...this.hiders]) hide();
    this.hiders.clear();
  }

  /** Stops and clears the TOTP codes shown. */
  stopTickers() {
    for (const stop of [...this.tickers]) stop();
    this.tickers.clear();
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
    try {
      this.trees.set(await api.folderTrees());
    } catch (e) {
      // A core older than version 11 has no folders: the vault is shown without them.
      this.trees.clear();
      if (/** @type {any} */ (e).code !== "unsupported_version") this.hooks.onError(/** @type {any} */ (e));
    }
    const ff = this.folderFilter();
    if (ff && !this.trees.get(ff.locker, ff.folder)) {
      // The folder shown was deleted or moved away by another device: back to its locker.
      this.filter = `casier:${ff.locker}`;
      this.hooks.onFilter(this.filter);
    }
    this.renderLockers();
    this.renderCounts();
    this.renderList();
  }

  /** Counts of the navigation: only when the whole vault is listed (no search, no trash). */
  renderCounts() {
    if (this.query || this.filter === "corbeille") return;
    const live = this.entries.filter((e) => !e.trash);
    byId("compte-tous").textContent = String(live.length);
    byId("compte-favoris").textContent = String(live.filter((e) => e.favorite).length);
    for (const [t, kinds] of Object.entries(TYPE_FILTERS)) {
      byId(`compte-${t}`).textContent = String(live.filter((e) => kinds.includes(e.kind)).length);
    }
  }

  renderLockers() {
    const ul = byId("liste-casiers");
    ul.replaceChildren(
      ...this.lockers.map((l) => {
        const count = this.entries.filter((e) => e.locker === l.id && !e.trash).length;
        const shared = l.personal ? undefined : this.shared.get(l.id);
        const button = h(
          "button",
          { class: "nav-lien", type: "button", "data-vue": "secrets", "data-filtre": `casier:${l.id}` },
          [
            l.personal ? icon("casier") : icon("membres", "marque-partage"),
            h("span", { class: "nav-nom nom-casier", text: l.name }),
            shared && !shared.access ? h("span", { class: "forme forme-triangle", "aria-hidden": "true" }) : null,
            h("span", { class: "compte", text: String(count), "aria-hidden": "true" }),
          ],
        );
        if (!l.personal) {
          const role = shared?.role ? `, rôle ${shared.role.toLowerCase()}` : "";
          const lost = shared && !shared.access ? ", accès perdu" : "";
          button.setAttribute("aria-label", `${l.name}, casier partagé${role}${lost}, ${count} secret${count > 1 ? "s" : ""}`);
        }
        if (this.filter === `casier:${l.id}`) button.setAttribute("aria-current", "page");
        if (!this.trees.hasFolders(l.id)) return h("li", {}, [button]);
        const open = !this.folded.has(l.id);
        return h("li", {}, [
          h("div", { class: "nav-ligne" }, [this.foldButton(l.id, l.name, open), button]),
          this.folderList(l.id, null, open, 0),
        ]);
      }),
    );
  }

  /**
   * The button that folds or unfolds a node of the navigation.
   * @param {string} key  Locker or folder.
   * @param {string} name
   * @param {boolean} open
   * @returns {HTMLElement}
   */
  foldButton(key, name, open) {
    const b = h("button", {
      class: "nav-replier",
      type: "button",
      "aria-expanded": open ? "true" : "false",
      "aria-label": `${open ? "Replier" : "Déplier"} ${name}`,
      title: open ? "Replier" : "Déplier",
      text: open ? "▾" : "▸",
    });
    b.addEventListener("click", () => {
      if (this.folded.has(key)) this.folded.delete(key);
      else this.folded.add(key);
      this.renderLockers();
    });
    return b;
  }

  /**
   * The folders of a locker under `parent`, with the number of secrets each holds directly.
   * @param {string} locker
   * @param {string | null} parent
   * @param {boolean} open
   * @param {number} depth
   * @returns {HTMLElement}
   */
  folderList(locker, parent, open, depth) {
    const ul = h("ul", { class: "nav-dossiers", hidden: !open });
    if (depth > 32) return ul;
    for (const f of this.trees.children(locker, parent)) {
      const count = this.entries.filter(
        (e) => e.locker === locker && !e.trash && this.trees.folderOf(locker, e.id) === f.id,
      ).length;
      const filter = `dossier:${locker}:${f.id}`;
      const button = h("button", { class: "nav-lien", type: "button", "data-vue": "secrets", "data-filtre": filter }, [
        icon("dossier"),
        h("span", { class: "nav-nom", text: f.name }),
        h("span", { class: "compte", text: String(count), "aria-hidden": "true" }),
      ]);
      button.setAttribute("aria-label", `${f.name}, dossier, ${count} secret${count > 1 ? "s" : ""}`);
      if (this.filter === filter) button.setAttribute("aria-current", "page");
      const kids = this.trees.children(locker, f.id).length > 0;
      const unfolded = !this.folded.has(f.id);
      const line = h("div", { class: "nav-ligne" }, [
        kids ? this.foldButton(f.id, f.name, unfolded) : h("span", { class: "nav-replier nav-replier-vide", "aria-hidden": "true" }),
        button,
      ]);
      ul.append(h("li", {}, [line, kids ? this.folderList(locker, f.id, unfolded, depth + 1) : null]));
    }
    return ul;
  }

  /** Role and members button above the list of a shared locker, and the folder actions. */
  renderLockerHeader() {
    this.renderFolderHeader();
    const id = this.lockerFilter();
    const locker = id ? this.lockers.find((l) => l.id === id) : undefined;
    const box = byId("liste-casier-partage");
    box.hidden = !locker || locker.personal;
    if (!locker || locker.personal) return;
    const info = this.shared.get(locker.id);
    byId("liste-casier-role").textContent = !info
      ? "Casier partagé."
      : !info.access
        ? "Accès perdu : le serveur ne vous sert plus ce casier."
        : `Casier partagé · votre rôle : ${info.role ? info.role.toLowerCase() : "aucun"}${info.writes ? "" : " (lecture seule)"}.`;
  }

  /** Path and actions of the folder shown, or the creation of a folder in the locker shown. */
  renderFolderHeader() {
    const locker = this.lockerFilter();
    const ff = this.folderFilter();
    const box = byId("liste-dossier");
    box.hidden = !locker || this.filter === "corbeille" || !this.writes(locker);
    if (box.hidden || !locker) return;
    const l = this.lockers.find((x) => x.id === locker);
    byId("liste-dossier-chemin").textContent = ff
      ? `${l?.name ?? "Casier"} / ${this.trees.path(ff.locker, ff.folder)}`
      : this.trees.hasFolders(locker)
        ? "Secrets à la racine du casier."
        : "Rangez les secrets de ce casier dans des dossiers.";
    for (const id of ["dossier-renommer", "dossier-deplacer", "dossier-supprimer"]) byId(id).hidden = !ff;
  }

  /** @returns {string} */
  filterTitle() {
    if (this.filter === "favoris") return "Favoris";
    if (this.filter === "corbeille") return "Corbeille";
    if (this.filter === "type:password") return "Mots de passe";
    if (this.filter === "type:ssh_key") return "Clés SSH";
    if (this.filter === "type:connexion") return "Connexions";
    if (this.filter === "type:note") return "Notes";
    if (this.filter.startsWith("casier:")) {
      const id = this.filter.slice("casier:".length);
      return this.lockers.find((l) => l.id === id)?.name ?? "Casier";
    }
    const ff = this.folderFilter();
    if (ff) return this.trees.get(ff.locker, ff.folder)?.name ?? "Dossier";
    return "Tous les secrets";
  }

  renderList() {
    const f = this.filter;
    this.shown = this.entries.filter((e) => {
      if (f === "corbeille") return e.trash;
      if (e.trash) return false;
      if (f === "favoris") return e.favorite;
      if (f.startsWith("type:")) return (TYPE_FILTERS[f.slice("type:".length)] ?? []).includes(e.kind);
      // A locker lists the secrets of its root; a folder, those it holds directly (ADR 0076).
      if (f.startsWith("casier:")) {
        return e.locker === f.slice("casier:".length) && this.trees.folderOf(e.locker, e.id) === null;
      }
      if (f.startsWith("dossier:")) {
        const ff = this.folderFilter();
        return !!ff && e.locker === ff.locker && this.trees.folderOf(e.locker, e.id) === ff.folder;
      }
      return true;
    });
    byId("liste-titre").textContent = this.filterTitle();
    this.renderLockerHeader();
    const n = this.shown.length;
    const count = byId("liste-compte");
    count.textContent = n === 0 ? "" : String(n);
    count.setAttribute("aria-label", n === 1 ? "1 secret" : `${n} secrets`);
    const empty = byId("liste-vide");
    if (n === 0) {
      empty.textContent = this.query
        ? "Aucun secret ne correspond à cette recherche."
        : f === "corbeille"
          ? "La corbeille est vide."
          : f === "favoris"
            ? "Aucun favori. Marquez un secret comme favori depuis sa fiche."
            : f.startsWith("dossier:")
              ? "Ce dossier ne contient aucun secret directement."
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
            h("span", { class: "vignette", "aria-hidden": "true" }, [icon(TYPE_ICONS[e.kind] ?? TYPE_ICONS.unknown)]),
            h("span", { class: "element-titre", text: e.title }),
            e.favorite
              ? h("span", { class: "element-favori", title: "Favori" }, [icon("favori", "icone-pleine")])
              : h("span"),
            h("span", { class: "element-sous", text: this.withPath(e, subtitle(e)) }),
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

  /**
   * A line of the list, with the folder of the secret when the list mixes several places
   * (search, whole vault, type, favourites).
   * @param {Entry} e
   * @param {string} text
   * @returns {string}
   */
  withPath(e, text) {
    if (this.filter.startsWith("casier:") || this.filter.startsWith("dossier:")) return text;
    const folder = this.trees.folderOf(e.locker, e.id);
    return folder ? `${text} · ${this.trees.path(e.locker, folder)}` : text;
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
    this.recordToken += 1;
    this.hideAll();
    this.stopTickers();
    const entry = this.selected();
    byId("fiche-vide").hidden = !!entry;
    byId("fiche-contenu").hidden = !entry;
    const fields = byId("fiche-champs");
    fields.replaceChildren();
    if (!entry) return;
    const locker = this.lockers.find((l) => l.id === entry.locker);
    const folder = this.trees.folderOf(entry.locker, entry.id);
    byId("fiche-type").textContent =
      (TYPE_NAMES[entry.kind] ?? TYPE_NAMES.unknown) +
      (locker ? ` · casier ${locker.name}${locker.personal ? "" : ", partagé"}` : "") +
      (folder ? ` · dossier ${this.trees.path(entry.locker, folder)}` : "");
    byId("fiche-deplacer").hidden =
      entry.trash || !this.trees.hasFolders(entry.locker) || !this.writes(entry.locker);
    byId("fiche-icone").replaceChildren(icon(TYPE_ICONS[entry.kind] ?? TYPE_ICONS.unknown));
    byId("fiche-titre").textContent = entry.title;
    /** @type {HTMLDetailsElement} */ (byId("fiche-menu")).open = false;
    const fav = byId("fiche-favori");
    fav.setAttribute("aria-pressed", entry.favorite ? "true" : "false");
    fav.setAttribute("aria-label", entry.favorite ? "Retirer des favoris" : "Ajouter aux favoris");
    fav.title = entry.favorite ? "Retirer des favoris" : "Ajouter aux favoris";
    fav.hidden = entry.trash;
    byId("fiche-modifier").hidden =
      entry.trash || !["password", "note", "totp", "ssh_connection", "rdp_connection"].includes(entry.kind);
    byId("fiche-supprimer-texte").textContent = entry.trash ? "Supprimer définitivement" : "Mettre à la corbeille";
    byId("fiche-restaurer").hidden = !entry.trash;

    const main = byId("fiche-principales");
    main.replaceChildren();
    main.hidden = true;
    if (entry.trash) {
      fields.append(info("État", "Dans la corbeille. Restaurez-le pour le retrouver dans la liste."));
    }
    if (entry.kind === "ssh_connection" || entry.kind === "rdp_connection") {
      void this.renderConnection(entry, this.recordToken);
    } else if (["password", "note", "ssh_key", "totp"].includes(entry.kind)) {
      void this.renderFields(entry, this.recordToken);
    } else {
      fields.append(info("Contenu", "Ce type de secret s'affichera dans une prochaine version de l'application."));
    }
  }

  /**
   * Names of the fields the current version of a secret holds, read from its history: the
   * core lists the fields present, never a value (`docs/api-locale.md` § 16.2). `null` when
   * the core does not tell (older core, refusal): every field is then drawn as before.
   * @param {import("./api.js").SecretRef} ref
   * @returns {Promise<Set<string> | null>}
   */
  async presentFields(ref) {
    try {
      const versions = await api.history(ref);
      return versions.length ? new Set(versions[0].fields) : null;
    } catch {
      return null;
    }
  }

  /**
   * The fields of a password, a note, an SSH key or a TOTP code. An empty optional field
   * (notes, passphrase, TOTP) is left out; an empty main field says so, without reveal or
   * copy buttons.
   * @param {Entry} entry
   * @param {number} token  Drawing this record belongs to; a later one cancels it.
   */
  async renderFields(entry, token) {
    const ref = { locker: entry.locker, id: entry.id };
    const present = await this.presentFields(ref);
    if (token !== this.recordToken) return;
    /** @param {string} f  A field name of the history (`docs/api-locale.md` § 16.2). */
    const has = (f) => present === null || present.has(f);
    const fields = byId("fiche-champs");
    // The most frequent action of each type comes first, above the fields.
    const main = byId("fiche-principales");
    const quick = /** @type {Record<string, [FieldName, string]>} */ ({
      password: ["password", "Mot de passe"],
      note: ["notes", "Contenu"],
      ssh_key: ["ssh_public_key", "Clé publique"],
    })[entry.kind];
    // A TOTP code: its own secret's main action, and the second one of a password.
    const totp = (entry.kind === "password" || entry.kind === "totp") && has("totp") && !entry.trash;
    if (totp && entry.kind === "totp") main.append(this.totpCopyButton(ref, "bouton-principal"));
    if (quick && !entry.trash) {
      const [field, label] = quick;
      if (has(field)) {
        const b = h("button", { class: "bouton bouton-principal", type: "button" }, [
          icon("copier"),
          `Copier ${label === "Contenu" ? "le contenu" : label === "Mot de passe" ? "le mot de passe" : "la clé publique"}`,
        ]);
        b.addEventListener("click", () => void this.copy(ref, field, label));
        main.append(b);
      }
      if (entry.kind === "password" && entry.username) {
        const u = h("button", { class: `bouton ${has("password") ? "bouton-secondaire" : "bouton-principal"}`, type: "button" }, [
          icon("copier"),
          "Copier l'identifiant",
        ]);
        u.addEventListener("click", () => void this.copy(ref, "username", "Identifiant"));
        main.append(u);
      }
      if (totp) main.append(this.totpCopyButton(ref, "bouton-secondaire"));
    }
    if (!entry.trash) {
      /** @type {import("./api.js").TypedWhat[]} */
      const offered = [];
      if (entry.kind === "password") {
        if (entry.username && has("password")) offered.push("username_password");
        if (has("password")) offered.push("password");
        if (entry.username) offered.push("username");
      }
      if ((entry.kind === "password" || entry.kind === "note") && has("notes")) offered.push("notes");
      if (entry.kind === "ssh_key" && has("ssh_passphrase")) offered.push("ssh_passphrase");
      if (entry.kind === "totp" && entry.username) offered.push("username");
      const type = this.hooks.autoType.button(ref, entry.title, offered);
      if (type) main.append(type);
    }
    main.hidden = main.childElementCount === 0;
    /**
     * @param {string} label
     * @param {FieldName} field
     */
    const required = (label, field) => (has(field) ? this.secretField(label, ref, field) : emptyField(label));
    if (entry.kind === "password") {
      if (entry.username) fields.append(this.plainField("Identifiant", entry.username, ref, "username"));
      fields.append(required("Mot de passe", "password"));
      if (totp) fields.append(this.totpField(ref, token));
      if (entry.hosts.length) fields.append(listField("Sites", entry.hosts, "mono"));
      if (entry.tags.length) fields.append(listField("Étiquettes", entry.tags, "etiquette"));
      if (has("notes")) fields.append(this.secretField("Notes", ref, "notes"));
    } else if (entry.kind === "note") {
      if (entry.tags.length) fields.append(listField("Étiquettes", entry.tags, "etiquette"));
      fields.append(required("Contenu", "notes"));
    } else if (entry.kind === "totp") {
      if (entry.username) fields.append(this.plainField("Identifiant", entry.username, ref, "username"));
      if (entry.trash || !has("totp")) fields.append(emptyField("Code TOTP"));
      else fields.append(this.totpField(ref, token));
      if (entry.hosts.length) fields.append(listField("Sites", entry.hosts, "mono"));
      if (entry.tags.length) fields.append(listField("Étiquettes", entry.tags, "etiquette"));
      if (has("notes")) fields.append(this.secretField("Notes", ref, "notes"));
    } else if (entry.kind === "ssh_key") {
      if (entry.username) fields.append(this.plainField("Identifiant", entry.username, ref, "username"));
      fields.append(required("Clé publique", "ssh_public_key"));
      if (has("ssh_passphrase")) fields.append(this.secretField("Phrase de passe", ref, "ssh_passphrase"));
      if (entry.tags.length) fields.append(listField("Étiquettes", entry.tags, "etiquette"));
    }
  }

  /**
   * The button that copies the current TOTP code, by the Rust process: the page never holds
   * the copied value.
   * @param {import("./api.js").SecretRef} ref
   * @param {string} style  bouton-principal or bouton-secondaire.
   */
  totpCopyButton(ref, style) {
    const b = h("button", { class: `bouton ${style}`, type: "button" }, [icon("totp"), "Copier le code TOTP"]);
    b.addEventListener("click", () => void this.copyTotp(ref));
    return b;
  }

  /** @param {import("./api.js").SecretRef} ref */
  async copyTotp(ref) {
    try {
      const s = await api.totpCopy(ref, false);
      announce(`Code TOTP copié. Le presse-papiers sera effacé dans ${s} s.`);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "not_found") announce("Ce secret n'a plus de TOTP.");
      else this.hooks.onError(err);
    }
  }

  /**
   * The TOTP code of a secret: computed by the core, shown grouped (« 287 082 »), with a ring
   * that empties until the code changes. The code is asked again at the end of each period,
   * only while the record is shown; the core does not count it as activity, so an open record
   * does not keep the vault open. The TOTP secret never reaches the page.
   * @param {import("./api.js").SecretRef} ref
   * @param {number} token  Drawing this record belongs to; a later one stops the refresh.
   */
  totpField(ref, token) {
    const value = h("span", { class: "code-totp", text: "··· ···" });
    const ring = svgRing();
    const left = h("span", { class: "totp-reste", "aria-hidden": "true" });
    const meta = h("span", { class: "decompte" });
    const copy = iconButton("copier", "Copier le code TOTP");
    copy.addEventListener("click", () => void this.copyTotp(ref));
    const row = h("div", { class: "champ-fiche" }, [
      h("dt", { text: "Code TOTP" }),
      h("dd", { class: "valeur-avec-etat" }, [h("span", {}, [value, meta]), h("span", { class: "totp-minuteur" }, [ring.svg, left])]),
      h("dd", { class: "actions-champ" }, [copy]),
    ]);
    let timer = 0;
    let fetchToken = 0;
    let remaining = 0;
    let period = 30;
    const stop = () => {
      clearInterval(timer);
      timer = 0;
      fetchToken += 1;
      value.textContent = "";
      this.tickers.delete(stop);
    };
    const draw = () => {
      ring.set(remaining / period, remaining <= 5);
      left.textContent = `${remaining} s`;
      row.classList.toggle("totp-bientot", remaining <= 5);
    };
    const load = async () => {
      const mine = ++fetchToken;
      /** @type {import("./api.js").TotpCode} */
      let c;
      try {
        c = await api.totpCode(ref);
      } catch (e) {
        if (mine !== fetchToken || token !== this.recordToken) return;
        stop();
        const err = /** @type {import("./api.js").ApiError} */ (e);
        if (err.code === "not_found") row.replaceWith(emptyField("Code TOTP"));
        else this.hooks.onError(err);
        return;
      }
      if (mine !== fetchToken || token !== this.recordToken) return;
      value.textContent = groupDigits(c.code);
      value.setAttribute("aria-label", `Code TOTP ${c.code.split("").join(" ")}`);
      period = c.period;
      remaining = c.seconds_left;
      const what = [c.issuer, `${c.digits} chiffres`, `toutes les ${c.period} s`, c.algorithm === "SHA-1" ? null : c.algorithm];
      meta.textContent = what.filter(Boolean).join(" · ");
      draw();
    };
    timer = window.setInterval(() => {
      if (token !== this.recordToken) {
        stop();
        return;
      }
      if (remaining > 0) remaining -= 1;
      if (remaining === 0) void load();
      else draw();
    }, 1000);
    this.tickers.add(stop);
    void load();
    return row;
  }

  /**
   * The record of a connection: read from the core, which resolves the links to the SSH key
   * and to the jump hosts. The password and the notes are not in the card; they are revealed
   * and copied one by one, like any secret field.
   * @param {Entry} entry
   * @param {number} token  Drawing this record belongs to; a later one cancels it.
   */
  async renderConnection(entry, token) {
    const ref = { locker: entry.locker, id: entry.id };
    const fields = byId("fiche-champs");
    const main = byId("fiche-principales");
    /** @type {import("./api.js").ConnectionCard} */
    let card;
    try {
      card = await api.connectionCard(ref);
    } catch (e) {
      if (token !== this.recordToken) return;
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "not_found") fields.append(info("Connexion", "Cette connexion n'est plus dans le coffre."));
      else this.hooks.onError(err);
      return;
    }
    if (token !== this.recordToken) return;
    if (!entry.trash) {
      if (card.has_password) {
        const b = h("button", { class: "bouton bouton-principal", type: "button" }, [icon("copier"), "Copier le mot de passe"]);
        b.addEventListener("click", () => void this.copy(ref, "password", "Mot de passe"));
        main.append(b);
      }
      if (card.username) {
        const u = h("button", { class: `bouton ${card.has_password ? "bouton-secondaire" : "bouton-principal"}`, type: "button" }, [
          icon("copier"),
          "Copier l'identifiant",
        ]);
        u.addEventListener("click", () => void this.copy(ref, "username", "Identifiant"));
        main.append(u);
      }
      /** @type {import("./api.js").TypedWhat[]} */
      const offered = [];
      if (card.username && card.has_password) offered.push("username_password");
      if (card.has_password) offered.push("password");
      if (card.username) offered.push("username");
      const type = this.hooks.autoType.button(ref, entry.title, offered);
      if (type) main.append(type);
      main.hidden = main.childElementCount === 0;
    }
    const custom = card.port !== null && card.port !== (card.kind === "rdp" ? 3389 : 22);
    fields.append(
      h("div", { class: "champ-fiche" }, [
        h("dt", { text: "Hôte" }),
        h("dd", {}, [
          h("span", { class: "valeur-secrete", text: card.host ?? "" }),
          h("span", { class: "maillon-sous", text: ` · port ${card.effective_port}${custom ? "" : " (par défaut)"}` }),
        ]),
      ]),
    );
    if (card.username) fields.append(this.plainField("Identifiant", card.username, ref, "username"));
    if (card.domain) fields.append(info("Domaine", card.domain));
    if (card.has_password) fields.append(this.secretField("Mot de passe", ref, "password"));
    if (card.ssh_key) {
      fields.append(
        h("div", { class: "champ-fiche" }, [h("dt", { text: "Clé SSH" }), h("dd", {}, [h("ul", { class: "chaine" }, [this.linkItem(card.ssh_key, "cle")])])]),
      );
    }
    if (card.jumps.length) {
      fields.append(
        h("div", { class: "champ-fiche" }, [
          h("dt", { text: card.jumps.length > 1 ? "Rebonds" : "Rebond" }),
          h("dd", {}, [h("ol", { class: "chaine" }, card.jumps.map((j) => this.linkItem(j, "terminal")))]),
        ]),
      );
    }
    if (card.host_key) {
      fields.append(
        h("div", { class: "champ-fiche" }, [h("dt", { text: "Empreinte de l'hôte" }), h("dd", { class: "valeur-secrete", text: card.host_key })]),
      );
    }
    if (card.tags.length) fields.append(listField("Étiquettes", card.tags, "etiquette"));
    if (card.has_notes) fields.append(this.secretField("Notes", ref, "notes"));
  }

  /**
   * One link of a connection: the title of its target, which opens its record, and what the
   * core says of it when it is not usable.
   * @param {import("./api.js").ResolvedLink} link
   * @param {string} iconName
   */
  linkItem(link, iconName) {
    const where = link.host ? `${link.username ? `${link.username}@` : ""}${link.host}${link.port ? `:${link.port}` : ""}` : "";
    const known = this.entries.some((e) => e.id === link.id && !e.trash);
    /** @type {HTMLElement} */
    let name;
    if (link.title && known) {
      name = h("button", { class: "lien", type: "button", text: link.title });
      name.addEventListener("click", () => this.showSecret(link.id));
    } else {
      name = h("span", { text: link.title ?? "Cible inconnue" });
    }
    return h("li", { class: "maillon" }, [
      icon(iconName),
      name,
      where ? h("span", { class: "maillon-sous mono", text: where }) : null,
      link.state === "valid"
        ? null
        : h("span", { class: "etat etat-alerte" }, [h("span", { class: "forme forme-triangle", "aria-hidden": "true" }), LINK_STATES[link.state] ?? LINK_STATES.broken]),
    ]);
  }

  /**
   * Shows the record of a secret of the vault, leaving a filter that would hide it.
   * @param {string} id
   */
  showSecret(id) {
    if (!this.shown.some((e) => e.id === id)) {
      this.filter = "tous";
      this.hooks.onFilter("tous");
      this.renderList();
    }
    this.select(id, false);
  }

  /**
   * A field from the index (user name): shown, with a copy button.
   * @param {string} label
   * @param {string} value
   * @param {import("./api.js").SecretRef} ref
   * @param {FieldName} field
   */
  plainField(label, value, ref, field) {
    const copy = iconButton("copier", `Copier : ${label.toLowerCase()}`);
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
    const revealLabel = `Révéler : ${label.toLowerCase()}`;
    const hideLabel = `Masquer : ${label.toLowerCase()}`;
    const reveal = iconButton("oeil", revealLabel);
    reveal.setAttribute("aria-pressed", "false");
    const copy = iconButton("copier", `Copier : ${label.toLowerCase()}`);

    let timer = 0;
    let left = 0;
    const hide = () => {
      clearInterval(timer);
      timer = 0;
      value.textContent = mask();
      value.classList.add("valeur-masquee");
      countdown.textContent = "";
      setIconButton(reveal, "oeil", revealLabel);
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
          row.replaceWith(emptyField(label));
          return;
        }
        this.hooks.onError(err);
        return;
      }
      if (text === "") {
        // Present but empty (written by an older client or an import): nothing to show.
        row.replaceWith(emptyField(label));
        return;
      }
      value.textContent = text;
      text = "";
      value.classList.remove("valeur-masquee");
      setIconButton(reveal, "oeil-barre", hideLabel);
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
    const row = h("div", { class: "champ-fiche" }, [
      h("dt", { text: label }),
      h("dd", { class: "valeur-avec-etat" }, [h("span", {}, [value, countdown]), shape]),
      h("dd", { class: "actions-champ" }, [reveal, copy]),
    ]);
    return row;
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
    // Numbered like `hirzla history`: 1 is the current version.
    byId("historique-liste").replaceChildren(
      ...versions.map((v, i) => this.versionItem(ref, v, i + 1, i === 0)),
    );
    const dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-historique"));
    if (!dialog.open) dialog.showModal();
  }

  /**
   * One version in the history dialog.
   * @param {import("./api.js").SecretRef} ref
   * @param {import("./api.js").Version} v
   * @param {number} number  1 for the current version.
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

  /** Puts the selected secret in a folder of its locker, or at its root. */
  moveSelected() {
    const entry = this.selected();
    if (!entry || entry.trash) return;
    const ref = { locker: entry.locker, id: entry.id };
    this.folderDialog.open({
      title: `Déplacer « ${entry.title} »`,
      text: "Le secret reste dans son casier : seul son rangement change.",
      submit: "Déplacer",
      places: this.trees.places(entry.locker),
      place: this.trees.folderOf(entry.locker, entry.id) ?? "",
      run: async (_, place) => {
        await api.moveSecret(ref, place);
        announce(place ? `Rangé dans « ${this.trees.path(entry.locker, place)} ».` : "Rangé à la racine du casier.");
        await this.refresh();
      },
    });
  }

  /** A new folder in the folder shown, or at the root of the locker shown. */
  newFolder() {
    const locker = this.lockerFilter();
    if (!locker) return;
    const parent = this.folderFilter()?.folder ?? null;
    this.folderDialog.open({
      title: "Nouveau dossier",
      text: parent
        ? `Dans « ${this.trees.path(locker, parent)} ». Le nom du dossier est scellé comme le reste du casier.`
        : "À la racine du casier. Le nom du dossier est scellé comme le reste du casier.",
      submit: "Créer le dossier",
      name: "",
      run: async (name) => {
        await api.createFolder(locker, name, parent);
        if (parent) this.folded.delete(parent);
        this.folded.delete(locker);
        announce(`Dossier « ${name} » créé.`);
        await this.refresh();
      },
    });
  }

  renameFolder() {
    const ff = this.folderFilter();
    const folder = ff && this.trees.get(ff.locker, ff.folder);
    if (!ff || !folder) return;
    this.folderDialog.open({
      title: "Renommer le dossier",
      text: this.trees.path(ff.locker, ff.folder),
      submit: "Renommer",
      name: folder.name,
      run: async (name) => {
        await api.renameFolder(ff.locker, ff.folder, name);
        announce("Dossier renommé.");
        await this.refresh();
      },
    });
  }

  moveFolder() {
    const ff = this.folderFilter();
    const folder = ff && this.trees.get(ff.locker, ff.folder);
    if (!ff || !folder) return;
    this.folderDialog.open({
      title: `Déplacer « ${folder.name} »`,
      text: "Le dossier part avec ses sous-dossiers et ses secrets.",
      submit: "Déplacer",
      places: this.trees.places(ff.locker, this.trees.subtree(ff.locker, ff.folder)),
      place: folder.parent ?? "",
      run: async (_, place) => {
        await api.moveFolder(ff.locker, ff.folder, place);
        if (place) this.folded.delete(place);
        announce("Dossier déplacé.");
        await this.refresh();
      },
    });
  }

  async deleteFolder() {
    const ff = this.folderFilter();
    const folder = ff && this.trees.get(ff.locker, ff.folder);
    if (!ff || !folder) return;
    const under = this.trees.subtree(ff.locker, ff.folder);
    const subs = under.size - 1;
    // Counted from the listing, which holds every active secret when there is no search.
    const secrets = this.entries.filter((e) => {
      if (e.locker !== ff.locker || e.trash) return false;
      const f = this.trees.folderOf(e.locker, e.id);
      return f !== null && under.has(f);
    }).length;
    const what = this.query
      ? "Les secrets qu'ils contiennent iront à la corbeille."
      : secrets === 0
        ? "Aucun secret n'ira à la corbeille."
        : `${secrets} secret${secrets > 1 ? "s iront" : " ira"} à la corbeille.`;
    const ok = await confirmDialog(
      "Supprimer le dossier ?",
      `« ${this.trees.path(ff.locker, ff.folder)} »${subs > 0 ? ` et ses ${subs} sous-dossier${subs > 1 ? "s" : ""}` : ""} seront supprimés. ${what}`,
      "Supprimer",
    );
    if (!ok) return;
    try {
      const n = await api.deleteFolder(ff.locker, ff.folder);
      announce(n === 0 ? "Dossier supprimé." : `Dossier supprimé ; ${n} secret${n > 1 ? "s" : ""} mis à la corbeille.`);
      this.filter = `casier:${ff.locker}`;
      this.hooks.onFilter(this.filter);
      this.selectedId = null;
      await this.refresh();
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

/**
 * A button that shows only an icon; its name is its `aria-label` and its tooltip.
 * @param {string} name  Icon.
 * @param {string} label
 * @returns {HTMLButtonElement}
 */
function iconButton(name, label) {
  const b = /** @type {HTMLButtonElement} */ (h("button", { class: "bouton bouton-icone bouton-discret", type: "button" }));
  setIconButton(b, name, label);
  return b;
}

/**
 * @param {HTMLButtonElement} b
 * @param {string} name
 * @param {string} label
 */
function setIconButton(b, name, label) {
  b.replaceChildren(icon(name));
  b.setAttribute("aria-label", label);
  b.title = label;
}

/**
 * A code with its digits grouped by three (six digits) or four (seven or eight), easier to read
 * and to type: « 287 082 », « 9428 7082 ».
 * @param {string} code
 */
export function groupDigits(code) {
  const cut = code.length === 6 ? 3 : code.length > 6 ? 4 : 0;
  return cut ? `${code.slice(0, cut)} ${code.slice(cut)}` : code;
}

/**
 * The ring of a TOTP code: full at the start of a period, empty when the code changes.
 * @returns {{ svg: SVGSVGElement, set: (fraction: number, soon: boolean) => void }}
 */
function svgRing() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = /** @type {SVGSVGElement} */ (document.createElementNS(ns, "svg"));
  svg.setAttribute("class", "totp-anneau");
  svg.setAttribute("viewBox", "0 0 36 36");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const track = document.createElementNS(ns, "circle");
  const arc = document.createElementNS(ns, "circle");
  for (const c of [track, arc]) {
    c.setAttribute("cx", "18");
    c.setAttribute("cy", "18");
    c.setAttribute("r", "15");
  }
  track.setAttribute("class", "totp-anneau-fond");
  arc.setAttribute("class", "totp-anneau-arc");
  const length = 2 * Math.PI * 15;
  arc.setAttribute("stroke-dasharray", String(length));
  svg.append(track, arc);
  return {
    svg,
    set: (fraction, soon) => {
      const f = Math.max(0, Math.min(1, fraction));
      arc.setAttribute("stroke-dashoffset", String(length * (1 - f)));
      svg.classList.toggle("totp-anneau-bientot", soon);
    },
  };
}

/** @param {Entry} e */
function subtitle(e) {
  if (e.kind === "password") return e.username || e.hosts[0] || TYPE_NAMES.password;
  if (e.kind === "totp") return e.username ? `${TYPE_NAMES.totp} · ${e.username}` : TYPE_NAMES.totp;
  if (e.kind === "ssh_connection" || e.kind === "rdp_connection") {
    const where = `${e.username ? `${e.username}@` : ""}${e.hosts[0] ?? ""}`;
    return where ? `${e.kind === "rdp_connection" ? "RDP" : "SSH"} · ${where}` : TYPE_NAMES[e.kind];
  }
  return TYPE_NAMES[e.kind] ?? TYPE_NAMES.unknown;
}

/**
 * A field the secret does not hold: its name and "Vide", with nothing to reveal or copy.
 * @param {string} label
 */
function emptyField(label) {
  return h("div", { class: "champ-fiche" }, [h("dt", { text: label }), h("dd", { class: "valeur-vide", text: "Vide" })]);
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
