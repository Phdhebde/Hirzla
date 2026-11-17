// @ts-check
// Folders inside lockers (ADR 0076): the shown tree of each locker, as the core computes it,
// and the dialog that names or moves a folder, or puts a secret in one. A folder arranges the
// secrets of its locker; it carries no key and no right.

import { byId, showError } from "./dom.js";

/** @typedef {import("./api.js").ApiError} ApiError */
/** @typedef {import("./api.js").FolderTree} FolderTree */

/**
 * @typedef {{ id: string, name: string, parent: string | null }} Folder
 * @typedef {{ folders: Map<string, Folder>, children: Map<string, Folder[]>, place: Map<string, string> }} Tree
 */

/** Key of the root in `children`. */
const ROOT = "";

/** The trees of every locker this device holds. */
export class Trees {
  constructor() {
    /** @type {Map<string, Tree>} */
    this.byLocker = new Map();
  }

  /** @param {FolderTree[]} raw */
  set(raw) {
    this.byLocker = new Map();
    for (const t of raw) {
      /** @type {Tree} */
      const tree = { folders: new Map(), children: new Map(), place: new Map() };
      for (const f of t.folders) {
        tree.folders.set(f.id, f);
        const key = f.parent ?? ROOT;
        const siblings = tree.children.get(key);
        // The core gives the folders by name without case: siblings keep that order.
        if (siblings) siblings.push(f);
        else tree.children.set(key, [f]);
      }
      for (const [secret, folder] of t.placements) tree.place.set(secret, folder);
      this.byLocker.set(t.locker, tree);
    }
  }

  clear() {
    this.byLocker = new Map();
  }

  /** @param {string} locker @returns {boolean} */
  hasFolders(locker) {
    return (this.byLocker.get(locker)?.folders.size ?? 0) > 0;
  }

  /** @param {string} locker @param {string} folder @returns {Folder | undefined} */
  get(locker, folder) {
    return this.byLocker.get(locker)?.folders.get(folder);
  }

  /** Folder of a secret; `null`: the root. @param {string} locker @param {string} secret @returns {string | null} */
  folderOf(locker, secret) {
    return this.byLocker.get(locker)?.place.get(secret) ?? null;
  }

  /** @param {string} locker @param {string | null} parent @returns {Folder[]} */
  children(locker, parent) {
    return this.byLocker.get(locker)?.children.get(parent ?? ROOT) ?? [];
  }

  /** `A / B / C`. @param {string} locker @param {string} folder @returns {string} */
  path(locker, folder) {
    const tree = this.byLocker.get(locker);
    if (!tree) return "";
    /** @type {string[]} */
    const names = [];
    let at = tree.folders.get(folder);
    while (at && names.length <= tree.folders.size) {
      names.unshift(at.name);
      at = at.parent ? tree.folders.get(at.parent) : undefined;
    }
    return names.join(" / ");
  }

  /** The folder and every folder under it. @param {string} locker @param {string} folder @returns {Set<string>} */
  subtree(locker, folder) {
    const out = new Set([folder]);
    const stack = [folder];
    while (stack.length > 0) {
      const at = /** @type {string} */ (stack.pop());
      for (const c of this.children(locker, at)) {
        if (!out.has(c.id)) {
          out.add(c.id);
          stack.push(c.id);
        }
      }
    }
    return out;
  }

  /**
   * Every place of a locker, depth first: the root (`""`), then each folder with its path.
   * @param {string} locker
   * @param {Set<string>} [exclude]  Folders that may not be chosen.
   * @returns {{ value: string, label: string }[]}
   */
  places(locker, exclude = new Set()) {
    const out = [{ value: ROOT, label: "Racine du casier" }];
    /** @param {string | null} parent @param {number} depth */
    const walk = (parent, depth) => {
      if (depth > 32) return;
      for (const f of this.children(locker, parent)) {
        if (exclude.has(f.id)) continue;
        out.push({ value: f.id, label: this.path(locker, f.id) });
        walk(f.id, depth + 1);
      }
    };
    walk(null, 0);
    return out;
  }
}

/**
 * @typedef {object} FolderAsk
 * @property {string} title
 * @property {string} text
 * @property {string} submit  Label of the button.
 * @property {string | null} [name]  Shown and asked when not `undefined`.
 * @property {{ value: string, label: string }[]} [places]  A destination is asked when given.
 * @property {string} [place]  Destination chosen first.
 * @property {(name: string, place: string | null) => Promise<void>} run  `place` null: the root.
 */

/** The dialog of the folder actions: a name, a destination, or both. */
export class FolderDialog {
  /** @param {(e: ApiError) => boolean} handles  Refusals that change the screen. */
  constructor(handles) {
    this.handles = handles;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-dossier"));
    this.name = /** @type {HTMLInputElement} */ (byId("dossier-nom"));
    this.place = /** @type {HTMLSelectElement} */ (byId("dossier-destination"));
    this.button = /** @type {HTMLButtonElement} */ (byId("dossier-valider"));
    /** @type {FolderAsk | null} */
    this.ask = null;
    byId("form-dossier").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.submit();
    });
    this.dialog.addEventListener("close", () => {
      this.name.value = "";
      this.place.replaceChildren();
      this.ask = null;
      showError(byId("dossier-erreur"), null);
    });
  }

  /** @param {FolderAsk} ask */
  open(ask) {
    this.ask = ask;
    byId("dossier-titre").textContent = ask.title;
    byId("dossier-texte").textContent = ask.text;
    this.button.textContent = ask.submit;
    const askName = ask.name !== undefined;
    byId("dossier-champ-nom").hidden = !askName;
    this.name.value = ask.name ?? "";
    byId("dossier-champ-destination").hidden = !ask.places;
    this.place.replaceChildren(
      ...(ask.places ?? []).map((p) => {
        const o = document.createElement("option");
        o.value = p.value;
        o.textContent = p.label;
        return o;
      }),
    );
    if (ask.place !== undefined) this.place.value = ask.place;
    showError(byId("dossier-erreur"), null);
    this.dialog.showModal();
    (askName ? this.name : this.place).focus();
  }

  async submit() {
    const ask = this.ask;
    if (!ask) return;
    const error = byId("dossier-erreur");
    const name = this.name.value.trim();
    if (ask.name !== undefined && !name) {
      showError(error, "Donnez un nom au dossier.");
      this.name.focus();
      return;
    }
    if (new TextEncoder().encode(name).length > 255) {
      showError(error, "Nom trop long : 255 octets au plus.");
      this.name.focus();
      return;
    }
    const place = ask.places ? this.place.value || null : null;
    const label = this.button.textContent;
    this.button.disabled = true;
    try {
      await ask.run(name, place);
      this.dialog.close();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.handles(err)) this.dialog.close();
      else showError(error, err.message);
    } finally {
      this.button.disabled = false;
      this.button.textContent = label;
    }
  }
}
