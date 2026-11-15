// The function injected into the page's main frame by `scripting.executeScript`, on a click
// of the user in the popup. It must be self-contained: the browser serialises its source and
// runs it in the page, without the module around it.
//
// It acts only if the document it runs in is the top-level document of the expected origin,
// and only on visible fields of that document: never inside a frame, never on a field that is
// hidden, transparent, off the page, tiny, clipped or covered by another element.

/**
 * @param {'inspect' | 'fill' | 'read' | 'new_password'} action
 * @param {string} expectedOrigin
 * @param {{username?: string | null, password?: string} | null} data
 */
export function pageAgent(action, expectedOrigin, data) {
  const base = { origin: String(location.origin), top: window.top === window };
  if (base.origin !== expectedOrigin || !base.top) {
    return { ...base, ok: false, reason: 'origin' };
  }

  const MIN_SIZE = 8;
  const MIN_OPACITY = 0.5;

  /** Whether the user can see and reach `el`. */
  function visible(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
    if (el.type === 'hidden') return false;
    if (
      typeof el.checkVisibility === 'function' &&
      !el.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })
    ) {
      return false;
    }
    const own = getComputedStyle(el);
    if (own.visibility !== 'visible') return false;
    if (own.clipPath && own.clipPath !== 'none') return false;
    if (own.clip && own.clip !== 'auto') return false;
    let opacity = 1;
    for (let n = el; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === 'none') return false;
      opacity *= Number.parseFloat(s.opacity);
      if (s.clipPath && s.clipPath !== 'none' && n !== el) return false;
    }
    if (!(opacity >= MIN_OPACITY)) return false;
    let r = el.getBoundingClientRect();
    if (r.width < MIN_SIZE || r.height < MIN_SIZE) return false;
    const de = document.documentElement;
    const pageW = Math.max(de.scrollWidth, de.clientWidth);
    const pageH = Math.max(de.scrollHeight, de.clientHeight);
    const x = r.left + window.scrollX;
    const y = r.top + window.scrollY;
    if (x + r.width <= 0 || y + r.height <= 0 || x >= pageW || y >= pageH) return false;
    // Bring it into view if needed, then it must be the topmost element at its centre (a
    // label drawn over its own field is fine; anything else covering it is not).
    let cx = r.left + r.width / 2;
    let cy = r.top + r.height / 2;
    if (cx < 0 || cy < 0 || cx >= window.innerWidth || cy >= window.innerHeight) {
      el.scrollIntoView({ block: 'center', inline: 'center' });
      r = el.getBoundingClientRect();
      cx = r.left + r.width / 2;
      cy = r.top + r.height / 2;
    }
    const hit = document.elementFromPoint(cx, cy);
    if (hit === el) return true;
    const label = hit instanceof Element ? hit.closest('label') : null;
    return label !== null && label.control === el;
  }

  function inputsOf(scope) {
    const all = scope instanceof HTMLFormElement ? Array.from(scope.elements) : Array.from(document.querySelectorAll('input'));
    return all.filter((e) => e instanceof HTMLInputElement);
  }

  function passwordFields() {
    return Array.from(document.querySelectorAll('input')).filter(
      (e) => e instanceof HTMLInputElement && e.type === 'password',
    );
  }

  /** The visible user name field that goes with `pw`: in its form, before it. */
  function usernameFor(pw) {
    const before = inputsOf(pw.form ?? document).filter(
      (e) =>
        ['text', 'email', 'tel', ''].includes(e.type) &&
        (e.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0 &&
        visible(e),
    );
    const tagged = before.filter((e) => (e.autocomplete || '').split(/\s+/).includes('username'));
    if (tagged.length > 0) return tagged[tagged.length - 1];
    return before.length > 0 ? before[before.length - 1] : null;
  }

  function setValue(el, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  const all = passwordFields();
  const shown = all.filter(visible);
  if (shown.length === 0) {
    return { ...base, ok: false, reason: all.length > 0 ? 'hidden' : 'no_field' };
  }
  const pw = shown[0];

  switch (action) {
    case 'inspect':
      return { ...base, ok: true };
    case 'fill': {
      if (!data || typeof data.password !== 'string') return { ...base, ok: false, reason: 'inject' };
      const user = typeof data.username === 'string' ? usernameFor(pw) : null;
      if (user) setValue(user, data.username);
      setValue(pw, data.password);
      return { ...base, ok: true, username: user !== null };
    }
    case 'read': {
      if (pw.value === '') return { ...base, ok: false, reason: 'no_password' };
      const user = usernameFor(pw);
      return { ...base, ok: true, username: user ? user.value : null, password: pw.value };
    }
    case 'new_password': {
      if (!data || typeof data.password !== 'string') return { ...base, ok: false, reason: 'inject' };
      // A sign-up or change form: the new password and its confirmation, both visible, in
      // the same form as the first one.
      const targets = shown.filter((e) => e.form === pw.form).slice(0, 2);
      for (const t of targets) setValue(t, data.password);
      const user = usernameFor(pw);
      return { ...base, ok: true, username: user ? user.value : null };
    }
    default:
      return { ...base, ok: false, reason: 'inject' };
  }
}
