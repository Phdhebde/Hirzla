// Unit tests of the extension's pure decisions (node --test).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { alreadySaved, checkInjection, messageFor, sanitizeEntries } from '../../src/lib/decide.js';

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

test('a login is not saved twice for the same user name', () => {
  const entries = [{ username: 'max' }, { username: null }];
  assert.equal(alreadySaved(entries, 'max'), true);
  assert.equal(alreadySaved(entries, null), true);
  assert.equal(alreadySaved(entries, 'other'), false);
  assert.equal(alreadySaved([], 'max'), false);
});

test('every error has a French message, unknown codes a generic one', () => {
  for (const code of ['locked', 'not_found', 'hidden', 'frame', 'origin', 'host_unavailable']) {
    assert.ok(messageFor(code).length > 10, code);
  }
  assert.equal(messageFor('__proto__'), 'Opération impossible.');
  assert.equal(messageFor('<script>'), 'Opération impossible.');
});
