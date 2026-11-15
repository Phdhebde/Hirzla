// Web origins, as the core checks them (docs/api-locale.md § 6.1).
//
// The extension only works on pages served over https, and names a page by its serialised
// origin, `https://host[:port]`, computed by the browser's own URL parser (WHATWG URL
// Standard, the one the core uses too). The core repeats the check; this copy lets the popup
// say early that a page is not supported.

/**
 * The canonical https origin of `url`, or null.
 * @param {string} url
 * @returns {string | null}
 */
export function originOfUrl(url) {
  if (typeof url !== 'string' || url.length === 0 || url.length > 8192) return null;
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  // A URL carrying credentials is a classic disguise ("https://bank.example@evil.example").
  if (u.username !== '' || u.password !== '') return null;
  if (u.hostname === '') return null;
  const origin = u.origin;
  if (typeof origin !== 'string' || origin === 'null' || origin.length > 2048) return null;
  return origin;
}

/**
 * The host of a canonical origin (without port), for display and as a default title.
 * @param {string} origin
 * @returns {string}
 */
export function hostOf(origin) {
  return new URL(origin).hostname;
}
