// Passkeys (ADR 0079): the pure decisions of the extension, shared by the page script's
// relay, the background script and the consent window. Nothing here touches the browser API,
// so that it can be unit tested (node --test).
//
// The page only hands over what `navigator.credentials` received; the background script
// takes the origin from the browser (the message's sender), never from the page, and the core
// checks the relying party against it.

import { originOfUrl } from './origin.js';

/** Ids of the two content scripts registered while the passkey mode is on. */
export const SCRIPT_IDS = ['hirzla-passkey-page', 'hirzla-passkey-relay'];
/** Host permission asked for when the mode is turned on, and given back when it is off. */
export const ORIGINS = ['https://*/*'];

/** The content scripts of the mode: top frame only, before the page's own scripts. */
export const CONTENT_SCRIPTS = [
  {
    id: SCRIPT_IDS[0],
    matches: ORIGINS,
    js: ['passkey-page.js'],
    runAt: 'document_start',
    allFrames: false,
    world: 'MAIN',
  },
  {
    id: SCRIPT_IDS[1],
    matches: ORIGINS,
    js: ['passkey-relay.js'],
    runAt: 'document_start',
    allFrames: false,
  },
];

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Base64url without padding of bytes.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toB64u(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += B64[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += B64[n & 63];
  }
  return out;
}

/**
 * Bytes of base64url without padding, or null.
 * @param {string} text
 * @returns {Uint8Array | null}
 */
export function fromB64u(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    return null;
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    const c = [0, 1, 2, 3].map((k) => (i + k < text.length ? B64.indexOf(text[i + k]) : 0));
    const n = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3];
    out[o++] = (n >> 16) & 255;
    if (i + 2 < text.length) out[o++] = (n >> 8) & 255;
    if (i + 3 < text.length) out[o++] = n & 255;
  }
  return out;
}

/**
 * The bytes of a BufferSource (ArrayBuffer or a view on one), or null.
 * @param {unknown} source
 * @returns {Uint8Array | null}
 */
export function bytesOf(source) {
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  return null;
}

function uv(value) {
  return ['required', 'preferred', 'discouraged'].includes(value) ? value : 'preferred';
}

function idList(list) {
  if (list === undefined) return '';
  if (!Array.isArray(list) || list.length > 64) return null;
  const out = [];
  for (const d of list) {
    if (!d || typeof d !== 'object') return null;
    if (d.type !== undefined && d.type !== 'public-key') continue;
    const b = typeof d.id === 'string' ? fromB64u(d.id) : bytesOf(d.id);
    if (!b || b.length === 0 || b.length > 1023) return null;
    out.push(toB64u(b));
  }
  return out.join(',');
}

/**
 * The serialisable form of `navigator.credentials.create({publicKey})`, as the page script
 * sends it to the relay: bytes in base64url, lists as arrays. Null if it is not a request
 * Hirzla can answer (the browser's own authenticator then takes it).
 * @param {any} pk the `publicKey` member
 * @returns {object | null}
 */
export function serializeCreate(pk) {
  if (!pk || typeof pk !== 'object') return null;
  const challenge = bytesOf(pk.challenge);
  const userId = bytesOf(pk.user?.id);
  if (!challenge || !userId || typeof pk.rp !== 'object' || pk.rp === null) return null;
  if (!Array.isArray(pk.pubKeyCredParams)) return null;
  const algs = pk.pubKeyCredParams
    .filter((p) => p && p.type === 'public-key' && Number.isInteger(p.alg))
    .map((p) => p.alg);
  const exclude = idList(pk.excludeCredentials);
  if (exclude === null) return null;
  // An authenticator attached by cable or radio is asked for: not Hirzla.
  if (pk.authenticatorSelection?.authenticatorAttachment === 'cross-platform') return null;
  return {
    rpId: typeof pk.rp.id === 'string' ? pk.rp.id : null,
    rpName: typeof pk.rp.name === 'string' ? pk.rp.name : '',
    challenge: toB64u(challenge),
    userId: toB64u(userId),
    userName: typeof pk.user.name === 'string' ? pk.user.name : '',
    displayName: typeof pk.user.displayName === 'string' ? pk.user.displayName : '',
    algs: algs.length > 0 ? algs.join(',') : '-7,-257',
    exclude,
    uv: uv(pk.authenticatorSelection?.userVerification),
    credProps: pk.extensions?.credProps === true,
  };
}

/**
 * The serialisable form of `navigator.credentials.get({publicKey})`, or null.
 * @param {any} pk the `publicKey` member
 * @returns {object | null}
 */
export function serializeGet(pk) {
  if (!pk || typeof pk !== 'object') return null;
  const challenge = bytesOf(pk.challenge);
  if (!challenge) return null;
  const allow = idList(pk.allowCredentials);
  if (allow === null) return null;
  return {
    rpId: typeof pk.rpId === 'string' ? pk.rpId : null,
    challenge: toB64u(challenge),
    allow,
    uv: uv(pk.userVerification),
  };
}

/**
 * The page's origin from a message sender, as the browser tells it: top frame of a tab
 * only, https only. Null otherwise.
 * @param {{frameId?: number, tab?: object, origin?: string, url?: string} | undefined} sender
 * @returns {string | null}
 */
export function senderOrigin(sender) {
  if (!sender || sender.frameId !== 0 || !sender.tab) return null;
  const fromUrl = originOfUrl(sender.url);
  // Chromium gives `origin`; it must agree with the URL. Firefox gives the URL only.
  if (typeof sender.origin === 'string' && sender.origin !== fromUrl) return null;
  return fromUrl;
}

/**
 * The relying party identifier: the one asked for, or the page's host (WebAuthn § 5.1.3).
 * @param {string | null} rpId
 * @param {string} origin
 * @returns {string}
 */
export function effectiveRpId(rpId, origin) {
  return typeof rpId === 'string' && rpId.length > 0 ? rpId : new URL(origin).hostname;
}

/**
 * The message for the native host of a create request.
 * @param {string} origin
 * @param {ReturnType<typeof serializeCreate>} r
 */
export function createMessage(origin, r) {
  const m = {
    type: 'passkey_create',
    origin,
    rpId: effectiveRpId(r.rpId, origin),
    challenge: r.challenge,
    userId: r.userId,
    algs: r.algs,
    uv: r.uv,
  };
  if (r.rpName) m.rpName = r.rpName.slice(0, 1024);
  if (r.userName) m.userName = r.userName.slice(0, 1024);
  if (r.displayName) m.displayName = r.displayName.slice(0, 256);
  if (r.exclude) m.exclude = r.exclude;
  return m;
}

/**
 * The DOMException name the page receives for a refusal of the host or the core.
 * @param {string} error
 * @returns {string}
 */
export function domErrorFor(error) {
  switch (error) {
    case 'credential_excluded':
      return 'InvalidStateError';
    case 'algorithm_unsupported':
      return 'NotSupportedError';
    case 'invalid_input':
    case 'invalid_origin':
      return 'SecurityError';
    default:
      return 'NotAllowedError';
  }
}

/** French text of the consent window for an error of the host or the core. */
export function passkeyMessage(error) {
  switch (error) {
    case 'locked':
      return 'Le coffre est verrouillé. Ouvrez-le dans Hirzla, puis cliquez sur Réessayer.';
    case 'no_vault':
      return 'Aucun coffre sur ce poste. Créez-le dans l’application Hirzla.';
    case 'verification_required':
      return 'Ce site demande une vérification récente. Verrouillez puis rouvrez le coffre dans Hirzla (mot de passe, Touch ID ou Windows Hello), puis cliquez sur Réessayer.';
    case 'credential_excluded':
      return 'Une clé d’accès Hirzla existe déjà pour ce compte sur ce site.';
    case 'algorithm_unsupported':
      return 'Ce site demande un algorithme que Hirzla ne prend pas en charge.';
    case 'invalid_input':
    case 'invalid_origin':
      return 'Ce site ne peut pas utiliser cet identifiant de domaine : demande refusée.';
    case 'host_unavailable':
    case 'core_not_running':
      return 'Hirzla ne répond pas. Ouvrez l’application Hirzla, puis cliquez sur Réessayer.';
    default:
      return 'La demande n’a pas abouti.';
  }
}

/**
 * The options as the page script sent them, byte sources turned back into bytes:
 * `{$b: base64url}` becomes a Uint8Array. Depth and sizes are bounded.
 * @param {unknown} v
 * @returns {unknown}
 */
export function revive(v, depth = 0) {
  if (depth > 6) return null;
  if (Array.isArray(v)) return v.slice(0, 64).map((x) => revive(x, depth + 1));
  if (v && typeof v === 'object') {
    const keys = Object.keys(v);
    if (keys.length === 1 && keys[0] === '$b') return fromB64u(v.$b);
    const out = {};
    for (const k of keys.slice(0, 32)) out[k] = revive(v[k], depth + 1);
    return out;
  }
  return v;
}
