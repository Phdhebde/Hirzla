// @ts-check
// Display preferences of this window (never a secret): theme, reveal delay and interval of
// the background synchronisation (ADR 0048). Kept in the web view's local storage when
// available; defaults otherwise.

const KEY = "hirzla.preferences";

/** @typedef {{ theme: "systeme" | "clair" | "sombre", reveal_s: number, sync_min: number }} Prefs */

/** Intervals of the background synchronisation, in minutes; 0 turns it off. */
export const SYNC_MINUTES = [0, 1, 5, 15, 60];

/** @type {Prefs} */
const DEFAULTS = { theme: "systeme", reveal_s: 15, sync_min: 5 };

/** @returns {Prefs} */
export function loadPrefs() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    const p = JSON.parse(raw);
    const theme = ["systeme", "clair", "sombre"].includes(p.theme) ? p.theme : DEFAULTS.theme;
    const reveal_s = [5, 10, 15, 30].includes(p.reveal_s) ? p.reveal_s : DEFAULTS.reveal_s;
    const sync_min = SYNC_MINUTES.includes(p.sync_min) ? p.sync_min : DEFAULTS.sync_min;
    return { theme, reveal_s, sync_min };
  } catch {
    return { ...DEFAULTS };
  }
}

/** @param {Prefs} p */
export function savePrefs(p) {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    // Storage unavailable: the choice lasts for this session only.
  }
}

/** @param {Prefs["theme"]} theme */
export function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "clair") root.dataset.theme = "light";
  else if (theme === "sombre") root.dataset.theme = "dark";
  else delete root.dataset.theme;
}
