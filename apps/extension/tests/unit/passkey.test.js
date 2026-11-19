// Unit tests of the passkey mode's pure decisions (ADR 0079; node --test).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  CONTENT_SCRIPTS,
  createMessage,
  domErrorFor,
  effectiveRpId,
  fromB64u,
  passkeyMessage,
  revive,
  senderOrigin,
  serializeCreate,
  serializeGet,
  toB64u,
} from '../../src/lib/passkey.js';

const O = 'https://login.example.com';

test('base64url round trips without padding', () => {
  for (const len of [0, 1, 2, 3, 4, 5, 31, 32, 33, 64]) {
    const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + 251) & 255);
    const text = toB64u(bytes);
    assert.ok(!text.includes('='));
    assert.deepEqual(fromB64u(text), bytes);
    assert.equal(text, Buffer.from(bytes).toString('base64url'));
  }
  for (const bad of ['a', 'ab=c', 'a+b/', 'é', 12, null]) assert.equal(fromB64u(bad), null, String(bad));
});

test('the sender gives the origin: top frame of a tab, https, consistent', () => {
  const tab = { id: 4 };
  assert.equal(senderOrigin({ frameId: 0, tab, url: `${O}/signin?x=1`, origin: O }), O);
  // Firefox: no origin member.
  assert.equal(senderOrigin({ frameId: 0, tab, url: `${O}/signin` }), O);
  for (const s of [
    undefined,
    { frameId: 2, tab, url: `${O}/` },
    { frameId: 0, url: `${O}/` },
    { frameId: 0, tab, url: 'http://login.example.com/' },
    { frameId: 0, tab, url: `${O}/`, origin: 'https://evil.example' },
    { frameId: 0, tab, url: 'https://user@login.example.com/' },
  ]) {
    assert.equal(senderOrigin(s), null, JSON.stringify(s));
  }
});

function createOptions(extra = {}) {
  return {
    rp: { id: 'example.com', name: 'Exemple' },
    user: { id: new Uint8Array([1, 2, 3]), name: 'alice', displayName: 'Alice' },
    challenge: new Uint8Array(32).fill(0x11).buffer,
    pubKeyCredParams: [
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -7 },
      { type: 'other', alg: -35 },
    ],
    excludeCredentials: [{ type: 'public-key', id: new Uint8Array([1]) }],
    authenticatorSelection: { userVerification: 'required' },
    extensions: { credProps: true },
    ...extra,
  };
}

test('a create request is serialised for the host', () => {
  const r = serializeCreate(createOptions());
  assert.deepEqual(r, {
    rpId: 'example.com',
    rpName: 'Exemple',
    challenge: 'ERERERERERERERERERERERERERERERERERERERERERE',
    userId: 'AQID',
    userName: 'alice',
    displayName: 'Alice',
    algs: '-8,-7',
    exclude: 'AQ',
    uv: 'required',
    credProps: true,
  });
  assert.deepEqual(createMessage(O, r), {
    type: 'passkey_create',
    origin: O,
    rpId: 'example.com',
    rpName: 'Exemple',
    challenge: r.challenge,
    userId: 'AQID',
    userName: 'alice',
    displayName: 'Alice',
    algs: '-8,-7',
    exclude: 'AQ',
    uv: 'required',
  });
  // No rp.id: the page's host. No algorithm: the standard's default.
  const r2 = serializeCreate(createOptions({ rp: { name: 'Exemple' }, pubKeyCredParams: [] }));
  assert.equal(createMessage(O, r2).rpId, 'login.example.com');
  assert.equal(r2.algs, '-7,-257');
  assert.equal(r2.uv, 'required');
});

test('requests Hirzla cannot answer go to the browser', () => {
  assert.equal(serializeCreate(null), null);
  assert.equal(serializeCreate(createOptions({ challenge: 'abc' })), null);
  assert.equal(serializeCreate(createOptions({ user: { name: 'x' } })), null);
  assert.equal(
    serializeCreate(createOptions({ authenticatorSelection: { authenticatorAttachment: 'cross-platform' } })),
    null,
  );
  assert.equal(serializeCreate(createOptions({ excludeCredentials: [{ id: 'not bytes!' }] })), null);
  assert.equal(serializeGet({}), null);
});

test('a get request is serialised for the host', () => {
  const r = serializeGet({
    challenge: new Uint8Array(16).fill(0xfb),
    rpId: 'example.com',
    allowCredentials: [
      { type: 'public-key', id: new Uint8Array([7, 7]) },
      { type: 'public-key', id: new Uint8Array([8]) },
    ],
    userVerification: 'discouraged',
  });
  assert.deepEqual(r, {
    rpId: 'example.com',
    challenge: '-_v7-_v7-_v7-_v7-_v7-w',
    allow: 'Bwc,CA',
    uv: 'discouraged',
  });
  assert.equal(serializeGet({ challenge: new Uint8Array(16) }).uv, 'preferred');
  assert.equal(serializeGet({ challenge: new Uint8Array(16) }).allow, '');
});

test('the options sent by the page are revived', () => {
  const sent = { challenge: { $b: 'AQID' }, list: [{ id: { $b: 'Bw' } }], n: 1, s: 'x' };
  const back = revive(sent);
  assert.deepEqual(back.challenge, new Uint8Array([1, 2, 3]));
  assert.deepEqual(back.list[0].id, new Uint8Array([7]));
  assert.equal(back.n, 1);
  assert.equal(back.s, 'x');
  // Bounded depth.
  let deep = { $b: 'AQ' };
  for (let i = 0; i < 10; i++) deep = { x: deep };
  assert.doesNotThrow(() => revive(deep));
});

test('relying party identifier and errors', () => {
  assert.equal(effectiveRpId(null, O), 'login.example.com');
  assert.equal(effectiveRpId('', O), 'login.example.com');
  assert.equal(effectiveRpId('example.com', O), 'example.com');
  assert.equal(domErrorFor('credential_excluded'), 'InvalidStateError');
  assert.equal(domErrorFor('algorithm_unsupported'), 'NotSupportedError');
  assert.equal(domErrorFor('invalid_input'), 'SecurityError');
  assert.equal(domErrorFor('anything'), 'NotAllowedError');
  for (const e of ['locked', 'verification_required', 'credential_excluded', 'invalid_input', 'x']) {
    assert.ok(passkeyMessage(e).length > 10, e);
  }
});

test('the content scripts are top frame only, https only', () => {
  for (const s of CONTENT_SCRIPTS) {
    assert.deepEqual(s.matches, ['https://*/*']);
    assert.equal(s.allFrames, false);
    assert.equal(s.runAt, 'document_start');
  }
  assert.equal(CONTENT_SCRIPTS[0].world, 'MAIN');
  assert.equal(CONTENT_SCRIPTS[1].world, undefined);
});
