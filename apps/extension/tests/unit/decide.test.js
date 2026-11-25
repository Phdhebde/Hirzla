// Unit tests of the extension's pure decisions (node --test).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  alreadySaved,
  checkInjection,
  messageFor,
  sanitizeEntries,
  sanitizeVaults,
} from '../../src/lib/decide.js';

const O = 'https://bank.example';

test('an injection counts only from the main frame of the expected origin', () => {
  const good = [{ frameId: 0, result: { origin: O, top: true, ok: true } }];
  assert.deepEqual(checkInjection(good, O), { ok: true, value: good[0].result });

  const cases = [
    [undefined, 'frame'],
    [[], 'frame'],
    [[good[0], good[0]], 'frame'],
    [[{ frameId: 3, result: { origin: O, top: true, ok: true } }], 'frame'],
    [[{ frameId: 0, result: { origin: O, top: false, ok: true } }], 'frame'],
    [[{ frameId: 0, result: { origin: 'https://evil.example', top: true, ok: true } }], 'origin'],
    [[{ frameId: 0, result: { origin: 'https://login.bank.example', top: true, ok: true } }], 'origin'],
    [[{ frameId: 0, result: null }], 'inject'],
    [[{ frameId: 0, result: { origin: O, top: true, ok: false, reason: 'hidden' } }], 'hidden'],
    [[{ frameId: 0, result: { origin: O, top: true, ok: false } }], 'inject'],
    [[{ frameId: 0, result: { origin: O, top: true, ok: 'yes' } }], 'inject'],
  ];
  for (const [results, reason] of cases) {
    assert.deepEqual(checkInjection(results, O), { ok: false, reason }, JSON.stringify(results));
  }
});

test('entries from the host are filtered', () => {
  const hex = 'a'.repeat(32);
  assert.deepEqual(
    sanitizeEntries([
      { locker: hex, id: hex, title: 'Banque', username: 'max' },
      { locker: hex, id: hex, title: 'Sans identifiant' },
      { locker: 'x', id: hex, title: 'bad' },
      { locker: hex, id: hex.toUpperCase(), title: 'bad' },
      { locker: hex, id: hex, title: 3 },
      null,
      'x',
    ]),
    [
      { locker: hex, id: hex, title: 'Banque', username: 'max' },
      { locker: hex, id: hex, title: 'Sans identifiant', username: null },
    ],
  );
  assert.deepEqual(sanitizeEntries(undefined), []);
});

test('with several vaults, an entry keeps its vault or is dropped', () => {
  const hex = 'a'.repeat(32);
  const vault = 'b'.repeat(32);
  const base = { locker: hex, id: hex, title: 'Banque' };
  assert.deepEqual(
    sanitizeEntries([
      { ...base, vault, alias: 'Client X' },
      // A vault without alias, an alias without vault, a malformed identifier, an alias too
      // long or empty: the entry could be asked to the wrong vault, it is dropped.
      { ...base, vault },
      { ...base, alias: 'Client X' },
      { ...base, vault: 'B'.repeat(32), alias: 'Client X' },
      { ...base, vault, alias: 'x'.repeat(65) },
      { ...base, vault, alias: '' },
      { ...base, vault, alias: 7 },
    ]),
    [{ ...base, username: null, vault, alias: 'Client X' }],
  );
});

test('vaults from the host are filtered', () => {
  const a = 'a'.repeat(32);
  const b = 'b'.repeat(32);
  assert.deepEqual(
    sanitizeVaults([
      { vault: a, alias: 'Personnel', state: 'unlocked', default: true, target: true },
      { vault: b, alias: 'Client X', state: 'locked' },
      { vault: b, alias: 'Client X', state: 'open' },
      { vault: 'x', alias: 'Client X', state: 'locked' },
      { alias: 'Sans identifiant', state: 'locked' },
      { state: 'locked' },
      null,
    ]),
    [
      { vault: a, alias: 'Personnel', state: 'unlocked', isDefault: true, target: true },
      { vault: b, alias: 'Client X', state: 'locked', isDefault: false, target: false },
    ],
  );
  // Without the vault registry the host names no vault.
  assert.deepEqual(sanitizeVaults(undefined), []);
});

test('a login is not saved twice for the same user name', () => {
  const entries = [{ username: 'max' }, { username: null }];
  assert.equal(alreadySaved(entries, 'max'), true);
  assert.equal(alreadySaved(entries, null), true);
  assert.equal(alreadySaved(entries, 'other'), false);
  assert.equal(alreadySaved([], 'max'), false);
});

test('every error has a French message, unknown codes a generic one', () => {
  for (const code of ['locked', 'no_app', 'not_found', 'hidden', 'frame', 'origin', 'host_unavailable']) {
    assert.ok(messageFor(code).length > 10, code);
  }
  assert.equal(messageFor('__proto__'), 'Opération impossible.');
  assert.equal(messageFor('<script>'), 'Opération impossible.');
});
