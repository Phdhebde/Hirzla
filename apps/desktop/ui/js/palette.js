// @ts-check
// Quick access (Ctrl+K): find a secret or an action and use it from the keyboard. The
// palette reads the index through the same `List` as the list of secrets; it never holds a
// secret value: copying goes through the Rust process, like everywhere else.

import { api } from "./api.js";
import { announce, byId, h, icon } from "./dom.js";

/** @typedef {import("./api.js").Entry} Entry */

/**
 * @typedef {object} PaletteAction
 * @property {string} label
 * @property {string} icon
 * @property {string} [keys]  Shortcut shown on the right.
 * @property {() => void} run
 */

/**
 * @typedef {object} PaletteHooks
 * @property {(e: import("./api.js").ApiError) => boolean} onError  True when handled.
 * @property {(entry: Entry) => void} onOpen  Shows the record of this secret.
 * @property {() => PaletteAction[]} actions
 * @property {() => string | null} vaultName  Alias of the vault shown, when several are registered.
 * @property {(vault: string, entry: Entry) => void} onOpenIn  Shows this secret of another open vault.
 * @property {(kind: string) => string} iconOf
 */

const MAX_ROWS = 8;

export class Palette {
  /** @param {PaletteHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-palette"));
    this.input = /** @type {HTMLInputElement} */ (byId("palette-recherche"));
    this.list = byId("palette-liste");
    /** @type {{ entry?: Entry, action?: PaletteAction, vault?: { id: string, alias: string } }[]} */
    this.rows = [];
    this.active = 0;
    this.timer = 0;
    this.serial = 0;

    this.input.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.search(), 120);
    });
    this.input.addEventListener("keydown", (e) => this.onKey(e));
    this.dialog.addEventListener("close", () => this.wipe());
    // A click on the backdrop closes the palette.
    this.dialog.addEventListener("click", (e) => {
      if (e.target === this.dialog) this.dialog.close();
    });
  }

  open() {
    if (this.dialog.open) return;
    this.wipe();
    this.dialog.showModal();
    this.input.focus();
    void this.search();
  }

  /** Forgets what was typed and listed. */
  wipe() {
    clearTimeout(this.timer);
    this.serial += 1;
    this.input.value = "";
    this.rows = [];
    this.active = 0;
    this.list.replaceChildren();
    byId("palette-vide").hidden = true;
  }

  close() {
    if (this.dialog.open) this.dialog.close();
  }

  async search() {
    const serial = ++this.serial;
    const query = this.input.value.trim();
    /** @type {Entry[]} */
    let entries = [];
    try {
      entries = (await api.list(query, false)).entries.filter((e) => !e.trash);
    } catch (e) {
      if (!this.hooks.onError(/** @type {any} */ (e))) announce(/** @type {any} */ (e).message, 6000);
      this.close();
      return;
    }
    // Common search (ADR 0085): the other open vaults answer too, once something is typed.
    // A vault that does not answer is left out.
    /** @type {import("./api.js").VaultMatches[]} */
    let elsewhere = [];
    if (query && this.hooks.vaultName() !== null) {
      try {
        elsewhere = await api.searchVaults(query);
      } catch {
        elsewhere = [];
      }
    }
    if (serial !== this.serial) return;
    const needle = query.toLocaleLowerCase("fr");
    const actions = this.hooks.actions().filter((a) => !needle || a.label.toLocaleLowerCase("fr").includes(needle));
    // Without a query, favourites come first; actions always follow the secrets.
    if (!query) entries.sort((a, b) => Number(b.favorite) - Number(a.favorite));
    this.rows = [
      ...entries.slice(0, MAX_ROWS).map((entry) => ({ entry })),
      ...elsewhere.flatMap((m) => m.entries.map((entry) => ({ entry, vault: { id: m.vault, alias: m.alias } }))),
      ...actions.map((action) => ({ action })),
    ];
    this.active = 0;
    this.render();
  }

  render() {
    byId("palette-vide").hidden = this.rows.length > 0;
    this.list.hidden = this.rows.length === 0;
    // With several vaults, every secret carries the name of its vault.
    const here = this.hooks.vaultName();
    this.list.replaceChildren(
      ...this.rows.map((row, i) => {
        const e = row.entry;
        const a = row.action;
        const where = row.vault?.alias ?? here;
        const li = h(
          "li",
          { id: `palette-${i}`, class: "palette-ligne", role: "option", "aria-selected": i === this.active ? "true" : "false" },
          e
            ? [
                h("span", { class: "vignette", "aria-hidden": "true" }, [icon(this.hooks.iconOf(e.kind))]),
                h("span", { class: "palette-texte" }, [
                  h("span", { class: "element-titre", text: e.title }),
                  h("span", { class: "element-sous", text: e.username || e.hosts[0] || "" }),
                ]),
                where !== null ? h("span", { class: "etiquette palette-coffre", text: where }) : null,
              ]
            : [
                h("span", { class: "vignette vignette-action", "aria-hidden": "true" }, [icon(a?.icon ?? "secret")]),
                h("span", { class: "palette-texte" }, [h("span", { class: "element-titre", text: a?.label ?? "" })]),
                a?.keys ? h("span", { class: "touche", "aria-hidden": "true", text: a.keys }) : null,
              ],
        );
        li.addEventListener("click", () => {
          this.active = i;
          this.run(false);
        });
        return li;
      }),
    );
    if (this.rows.length > 0) this.input.setAttribute("aria-activedescendant", `palette-${this.active}`);
    else this.input.removeAttribute("aria-activedescendant");
  }

  /** @param {number} i */
  move(i) {
    if (this.rows.length === 0) return;
    this.active = Math.max(0, Math.min(i, this.rows.length - 1));
    for (const [n, li] of [...this.list.children].entries()) {
      li.setAttribute("aria-selected", n === this.active ? "true" : "false");
    }
    this.input.setAttribute("aria-activedescendant", `palette-${this.active}`);
    document.getElementById(`palette-${this.active}`)?.scrollIntoView({ block: "nearest" });
  }

  /** @param {KeyboardEvent} e */
  onKey(e) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      this.move(this.active + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      this.move(this.active - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      this.run(e.ctrlKey || e.metaKey);
    }
  }

  /**
   * Uses the active row: opens the secret, copies its password (Ctrl+Enter), or runs the
   * action.
   * @param {boolean} copy
   */
  run(copy) {
    const row = this.rows[this.active];
    if (!row) return;
    this.close();
    if (row.action) {
      row.action.run();
      return;
    }
    const entry = row.entry;
    if (!entry) return;
    if (row.vault) {
      // A secret of another vault: that vault is shown first; nothing is copied from afar.
      this.hooks.onOpenIn(row.vault.id, entry);
      return;
    }
    if (copy && entry.kind === "password") {
      void api
        .copyField({ locker: entry.locker, id: entry.id }, "password")
        .then((s) => announce(`Mot de passe de « ${entry.title} » copié. Le presse-papiers sera effacé dans ${s} s.`))
        .catch((e) => {
          if (!this.hooks.onError(e)) announce(e.code === "not_found" ? "Mot de passe : aucune valeur." : e.message, 6000);
        });
      return;
    }
    this.hooks.onOpen(entry);
  }
}
