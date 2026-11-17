// @ts-check
// Typing a field into another application (ADR 0072). The page names the secret and what
// to type; the value never comes here. The Rust process steps aside, finds the application
// that takes the keyboard, and comes back with its name for the warning below, unless the
// user asked not to be warned for that application.

import { api } from "./api.js";
import { announce, byId, h, icon, showError } from "./dom.js";

/** @typedef {import("./api.js").TypedWhat} TypedWhat */
/** @typedef {import("./api.js").SecretRef} SecretRef */

/** What can be typed, in the order offered, with the words of the warning. */
/** @type {[TypedWhat, string, string][]} */
const CHOICES = [
  ["username_password", "L'identifiant, Tab, puis le mot de passe", "l'identifiant et le mot de passe"],
  ["password", "Le mot de passe", "le mot de passe"],
  ["username", "L'identifiant", "l'identifiant"],
  ["ssh_passphrase", "La phrase de passe", "la phrase de passe"],
  ["notes", "Le contenu ou les notes (une seule ligne)", "le contenu"],
];

/** `null` until asked; then whether this workstation can type into another application. */
/** @type {boolean | null} */
let available = null;

/** Asks once whether typing is available here. */
export async function loadAutoType() {
  if (available !== null) return available;
  try {
    available = await api.autoTypeAvailable();
  } catch {
    available = false;
  }
  return available;
}

export class AutoType {
  /** @param {(e: import("./api.js").ApiError) => boolean} onError  Handles a locked vault or a lost core. */
  constructor(onError) {
    this.onError = onError;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-saisie"));
    /** @type {SecretRef | null} */
    this.ref = null;
    this.title = "";
    /** @type {TypedWhat} */
    this.what = "password";
    this.busy = false;
    byId("form-saisie").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.next();
    });
    byId("saisie-annuler").addEventListener("click", () => this.dialog.close());
    this.dialog.addEventListener("close", () => {
      // Whatever closed the dialog, nothing stays waiting on the other side.
      void api.autoTypeCancel().catch(() => {});
      this.ref = null;
    });
  }

  /**
   * The button of a record, or null when typing is not available or nothing can be typed.
   * @param {SecretRef} ref
   * @param {string} title
   * @param {TypedWhat[]} offered
   * @returns {HTMLElement | null}
   */
  button(ref, title, offered) {
    if (!available || offered.length === 0) return null;
    const b = h("button", { class: "bouton bouton-secondaire", type: "button" }, [icon("clavier"), "Saisir dans une application…"]);
    b.addEventListener("click", () => this.open(ref, title, offered));
    return b;
  }

  /**
   * @param {SecretRef} ref
   * @param {string} title
   * @param {TypedWhat[]} offered
   */
  open(ref, title, offered) {
    this.ref = ref;
    this.title = title;
    this.step(false);
    showError(byId("saisie-erreur"), null);
    const list = byId("saisie-choix");
    list.replaceChildren(
      ...CHOICES.filter(([what]) => offered.includes(what)).map(([what, label], i) =>
        h("label", { class: "case" }, [h("input", { type: "radio", name: "saisie-quoi", value: what, checked: i === 0 }), ` ${label}`]),
      ),
    );
    this.dialog.showModal();
  }

  /** @param {boolean} warning  Second step: the warning that names the application. */
  step(warning) {
    byId("saisie-etape-choix").hidden = warning;
    byId("saisie-etape-avertissement").hidden = !warning;
    byId("saisie-valider").textContent = warning ? "Saisir" : "Continuer";
  }

  async next() {
    if (!this.ref || this.busy) return;
    const error = byId("saisie-erreur");
    showError(error, null);
    this.busy = true;
    try {
      if (byId("saisie-etape-avertissement").hidden) {
        const chosen = /** @type {HTMLInputElement | null} */ (this.dialog.querySelector("input[name=saisie-quoi]:checked"));
        if (!chosen) return;
        this.what = /** @type {TypedWhat} */ (chosen.value);
        const r = await api.autoTypePrepare(this.ref, this.what);
        if (r.typed) return this.done(r.target.name);
        this.warn(r.target);
      } else {
        const remember = /** @type {HTMLInputElement} */ (byId("saisie-ne-plus"));
        const name = byId("saisie-application").textContent ?? "";
        await api.autoTypeConfirm(remember.checked && !remember.disabled);
        this.done(name);
      }
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      // A refusal after the warning ends that attempt: back to the first step.
      this.step(false);
      if (err.code === "not_found") showError(error, "Ce champ est vide : rien à saisir.");
      else if (!this.onError(err)) showError(error, err.message);
      else this.dialog.close();
    } finally {
      this.busy = false;
    }
  }

  /** @param {import("./api.js").AutoTypeTarget} target */
  warn(target) {
    const words = CHOICES.find(([what]) => what === this.what)?.[2] ?? "la valeur";
    byId("saisie-quoi").textContent = words;
    byId("saisie-secret").textContent = this.title;
    byId("saisie-application").textContent = target.name;
    const path = byId("saisie-chemin");
    path.textContent = target.path;
    path.hidden = target.path === "";
    const window = byId("saisie-fenetre");
    window.textContent = target.title ? `Fenêtre : ${target.title}` : "";
    window.hidden = target.title === "";
    byId("saisie-terminal").hidden = !target.terminal;
    const remember = /** @type {HTMLInputElement} */ (byId("saisie-ne-plus"));
    remember.checked = false;
    remember.disabled = !target.can_remember;
    byId("saisie-ne-plus-ligne").hidden = !target.can_remember;
    this.step(true);
    byId("saisie-valider").focus();
  }

  /** @param {string} name */
  done(name) {
    this.dialog.close();
    announce(`Saisi dans ${name}. Validez vous-même dans l'application.`, 6000);
  }
}
