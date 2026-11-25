// @ts-check
// Several vaults on this workstation (ADR 0085, docs/api-locale.md § 25.10): one tab per
// registered vault, above every screen. The alias comes from the vault registry, which is
// readable without unlocking; nothing from inside a vault is shown here. With one vault the
// bar stays hidden and the application looks as it always did.

import { api } from "./api.js";
import { byId, h } from "./dom.js";

/** @typedef {import("./api.js").VaultInfo} VaultInfo */

/** Shape and wording of each state (square sealed, round open, triangle alert). */
/** @type {Record<string, [string, string]>} */
const STATES = {
  unlocked: ["forme-rond", "ouvert"],
  locked: ["forme-carre", "verrouillé"],
  absent: ["forme-triangle", "à créer"],
  unavailable: ["forme-triangle", "indisponible"],
};

/**
 * @typedef {object} VaultBarHooks
 * @property {(id: string) => void} onPick  The user chose another vault.
 */

export class VaultBar {
  /** @param {VaultBarHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    this.nav = byId("coffres");
    this.list = byId("coffres-liste");
    /** @type {VaultInfo[]} */
    this.vaults = [];
    this.shown = "";
    this.list.addEventListener("click", (ev) => {
      const tab = /** @type {HTMLElement} */ (ev.target).closest("[data-coffre]");
      const id = tab?.getAttribute("data-coffre");
      if (typeof id === "string" && !this.vaults.find((v) => v.id === id)?.active) this.hooks.onPick(id);
    });
  }

  /** Whether several vaults are registered. */
  get multiple() {
    return this.vaults.length > 1;
  }

  /** Alias of the active vault when several are registered, else null. */
  activeAlias() {
    return this.multiple ? (this.vaults.find((v) => v.active)?.alias ?? null) : null;
  }

  /** Reads the vaults again. A failure leaves the bar as it is: the status poll reports it. */
  async refresh() {
    try {
      this.vaults = await api.listVaults();
    } catch {
      return;
    }
    this.render();
  }

  /**
   * Makes another vault the active one.
   * @param {string} id
   * @returns {Promise<void>}
   */
  async select(id) {
    await api.selectVault(id);
    this.vaults = this.vaults.map((v) => ({ ...v, active: v.id === id }));
    this.render();
  }

  render() {
    const key = JSON.stringify(this.vaults);
    if (key === this.shown) return;
    this.shown = key;
    this.nav.hidden = !this.multiple;
    document.body.classList.toggle("plusieurs-coffres", this.multiple);
    if (!this.multiple) {
      this.list.replaceChildren();
      return;
    }
    const focused = document.activeElement?.getAttribute("data-coffre");
    this.list.replaceChildren(
      ...this.vaults.map((v) => {
        const [shape, word] = STATES[v.state] ?? STATES.unavailable;
        return h("li", {}, [
          h(
            "button",
            {
              class: "coffres-onglet",
              type: "button",
              "data-coffre": v.id,
              "aria-current": v.active ? "true" : null,
              title: `Coffre « ${v.alias} » : ${word}`,
            },
            [
              h("span", { class: `forme ${shape}`, "aria-hidden": "true" }),
              h("span", { text: v.alias }),
              h("span", { class: "visuellement-cache", text: `, ${word}${v.active ? ", coffre affiché" : ""}` }),
            ],
          ),
        ]);
      }),
    );
    if (typeof focused === "string") {
      for (const b of this.list.querySelectorAll("[data-coffre]")) {
        if (b.getAttribute("data-coffre") === focused) /** @type {HTMLElement} */ (b).focus();
      }
    }
  }
}
