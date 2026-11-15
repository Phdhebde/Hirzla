// @ts-check
// DOM helpers. Text always goes through textContent: nothing from the vault is ever parsed
// as HTML.

/**
 * @template {HTMLElement} T
 * @param {string} id
 * @returns {T}
 */
export function byId(id) {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`élément absent : ${id}`);
  }
  return /** @type {T} */ (el);
}

/**
 * Creates an element.
 * @param {string} tag
 * @param {Record<string, string | boolean | number | null | undefined>} [attrs]
 * @param {(Node | string | null | undefined | false)[]} [children]
 * @returns {HTMLElement}
 */
export function h(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = String(v);
    else if (k === "text") el.textContent = String(v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}

/**
 * Shows an error in an `.alerte` block, or hides it.
 * @param {HTMLElement} box
 * @param {string | null} message
 */
export function showError(box, message) {
  const p = box.querySelector("p");
  if (p) p.textContent = message ?? "";
  box.hidden = !message;
}

/**
 * Short announcement, read by screen readers and shown for a few seconds.
 * @param {string} text
 * @param {number} [ms]
 */
export function announce(text, ms = 4000) {
  const region = byId("annonces");
  const item = h("div", { class: "annonce", text });
  region.append(item);
  setTimeout(() => item.remove(), ms);
}

/**
 * Masked rendering of a secret, independent of its length.
 * @returns {string}
 */
export function mask() {
  return "••••••••••••";
}
