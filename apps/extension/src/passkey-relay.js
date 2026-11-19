// Passkey mode (ADR 0079 § 6): runs in the extension's isolated world of the page, top frame
// only, registered only while the mode is on. It carries the requests of passkey-page.js to
// the background script and its answers back. It adds nothing and decides nothing: the
// background script takes the page's origin from the browser, never from this message.
(() => {
  'use strict';
  const api = globalThis.browser ?? globalThis.chrome;
  const CHANNEL = 'hirzla-passkey';
  if (window.top !== window) return;

  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (ev.source !== window || !d || d.channel !== CHANNEL || d.dir !== 'request') return;
    if (!Number.isInteger(d.id) || (d.kind !== 'create' && d.kind !== 'get')) return;
    const reply = (result) =>
      window.postMessage({ channel: CHANNEL, dir: 'response', id: d.id, result }, window.location.origin);
    Promise.resolve(api.runtime.sendMessage({ passkey: d.kind, publicKey: d.publicKey }))
      .then((result) => reply(result && typeof result === 'object' ? result : { fallback: true }))
      .catch(() => reply({ fallback: true }));
  });
})();
