// Passkey mode (ADR 0079 § 6): runs in the page's own world, top frame only, registered only
// while the user has turned the mode on. It wraps `navigator.credentials.create` and `get`
// for `publicKey` requests and hands them to the relay (passkey-relay.js), which hands them to
// the background script. It never sees a key: only what the standard puts in the response to
// the site. Anything Hirzla does not answer goes to the browser's own functions.
(() => {
  'use strict';

  const creds = globalThis.navigator?.credentials;
  if (!creds || typeof creds.create !== 'function' || typeof creds.get !== 'function') return;
  if (typeof PublicKeyCredential !== 'function') return;

  const CHANNEL = 'hirzla-passkey';
  const browserCreate = creds.create.bind(creds);
  const browserGet = creds.get.bind(creds);
  const pending = new Map();
  let next = 1;

  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (ev.source !== window || !d || d.channel !== CHANNEL || d.dir !== 'response') return;
    const resolve = pending.get(d.id);
    if (!resolve) return;
    pending.delete(d.id);
    resolve(d.result);
  });

  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  function toB64u(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
      if (i + 1 < bytes.length) out += B64[(n >> 6) & 63];
      if (i + 2 < bytes.length) out += B64[n & 63];
    }
    return out;
  }

  function buf(text) {
    const out = new Uint8Array(Math.floor((text.length * 3) / 4));
    let o = 0;
    for (let i = 0; i < text.length; i += 4) {
      const c = [0, 1, 2, 3].map((k) => (i + k < text.length ? B64.indexOf(text[i + k]) : 0));
      const n = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3];
      out[o++] = (n >> 16) & 255;
      if (i + 2 < text.length) out[o++] = (n >> 8) & 255;
      if (i + 3 < text.length) out[o++] = n & 255;
    }
    return out.buffer;
  }

  /** A structured-clone-safe copy of the options: byte sources as {$b: base64url}. */
  function plain(v, depth = 0) {
    if (depth > 6) return null;
    if (v instanceof ArrayBuffer) return { $b: toB64u(new Uint8Array(v)) };
    if (ArrayBuffer.isView(v)) {
      return { $b: toB64u(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)) };
    }
    if (Array.isArray(v)) return v.slice(0, 64).map((x) => plain(x, depth + 1));
    if (v && typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v).slice(0, 32)) {
        if (k === 'signal') continue;
        out[k] = plain(v[k], depth + 1);
      }
      return out;
    }
    return typeof v === 'function' ? null : v;
  }

  function ask(kind, publicKey, signal) {
    return new Promise((resolve) => {
      const id = next++;
      pending.set(id, resolve);
      if (signal) {
        signal.addEventListener('abort', () => {
          if (pending.delete(id)) resolve({ aborted: true });
        });
      }
      window.postMessage(
        { channel: CHANNEL, dir: 'request', id, kind, publicKey: plain(publicKey) },
        window.location.origin,
      );
    });
  }

  function own(target, props) {
    for (const [k, v] of Object.entries(props)) {
      Object.defineProperty(target, k, { value: v, enumerable: true, configurable: true });
    }
    return target;
  }

  function credential(kind, r, credProps) {
    const rawId = buf(r.credential);
    let response;
    if (kind === 'create') {
      const authData = buf(r.authData);
      response = own(Object.create(globalThis.AuthenticatorAttestationResponse?.prototype ?? Object.prototype), {
        clientDataJSON: buf(r.clientData),
        attestationObject: buf(r.attestation),
        getAuthenticatorData: () => authData.slice(0),
        getPublicKey: () => buf(r.publicKey),
        getPublicKeyAlgorithm: () => r.alg,
        getTransports: () => ['internal', 'hybrid'],
      });
    } else {
      response = own(Object.create(globalThis.AuthenticatorAssertionResponse?.prototype ?? Object.prototype), {
        clientDataJSON: buf(r.clientData),
        authenticatorData: buf(r.authData),
        signature: buf(r.signature),
        userHandle: typeof r.userHandle === 'string' ? buf(r.userHandle) : null,
      });
    }
    const extensions = kind === 'create' && credProps ? { credProps: { rk: true } } : {};
    const json = () => {
      const base = { id: r.credential, rawId: r.credential, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: extensions };
      if (kind === 'create') {
        return {
          ...base,
          response: {
            clientDataJSON: r.clientData,
            attestationObject: r.attestation,
            authenticatorData: r.authData,
            publicKey: r.publicKey,
            publicKeyAlgorithm: r.alg,
            transports: ['internal', 'hybrid'],
          },
        };
      }
      return {
        ...base,
        response: {
          clientDataJSON: r.clientData,
          authenticatorData: r.authData,
          signature: r.signature,
          ...(typeof r.userHandle === 'string' ? { userHandle: r.userHandle } : {}),
        },
      };
    };
    return own(Object.create(PublicKeyCredential.prototype), {
      id: r.credential,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: () => ({ ...extensions }),
      toJSON: json,
    });
  }

  async function run(kind, options, fallback) {
    const publicKey = options?.publicKey;
    // Password and federated credentials, conditional mediation (autofill): the browser's.
    if (!publicKey || options.mediation === 'conditional') return fallback(options);
    if (options.signal?.aborted) throw new DOMException('Opération annulée.', 'AbortError');
    const result = await ask(kind, publicKey, options.signal);
    if (result?.aborted) throw new DOMException('Opération annulée.', 'AbortError');
    if (!result || result.fallback) return fallback(options);
    if (result.ok) return credential(kind, result, publicKey.extensions?.credProps === true);
    throw new DOMException('Demande refusée.', typeof result.error === 'string' ? result.error : 'NotAllowedError');
  }

  const create = function create(options) {
    return run('create', options, browserCreate);
  };
  const get = function get(options) {
    return run('get', options, browserGet);
  };
  Object.defineProperty(create, 'name', { value: 'create' });
  Object.defineProperty(get, 'name', { value: 'get' });
  creds.create = create;
  creds.get = get;
})();
