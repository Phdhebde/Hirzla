// Unit tests of the origin rule (node --test). Same cases as hirzla-core's origin tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { originOfUrl, hostOf } from '../../src/lib/origin.js';

test('https pages give their canonical origin', () => {
  assert.equal(originOfUrl('https://bank.example/login?x=1#y'), 'https://bank.example');
  assert.equal(originOfUrl('https://BANK.example/'), 'https://bank.example');
  assert.equal(originOfUrl('https://bank.example:443/'), 'https://bank.example');
  assert.equal(originOfUrl('https://bank.example:8443/a'), 'https://bank.example:8443');
  // IDNA: the A-label, as in the vault index.
  assert.equal(originOfUrl('https://bücher.example/'), 'https://xn--bcher-kva.example');
  assert.equal(hostOf('https://bank.example:8443'), 'bank.example');
});

test('anything else is not supported', () => {
  for (const url of [
    undefined,
    null,
    '',
    'bank.example',
    'http://bank.example/',
    'file:///etc/passwd',
    'chrome://settings',
    'chrome-extension://abcdef/popup.html',
    'moz-extension://abcdef/popup.html',
    'about:blank',
    'data:text/html,<input type=password>',
    'javascript:alert(1)',
    'blob:https://bank.example/0b3c',
    'https://bank.example@evil.example/',
    'https://user:pw@bank.example/',
    'https://',
  ]) {
    assert.equal(originOfUrl(url), null, String(url));
  }
});

test('look-alikes, subdomains and parents are other origins', () => {
  const bank = originOfUrl('https://bank.example/');
  for (const url of [
    'https://login.bank.example/',
    'https://www.bank.example/',
    'https://example/',
    'https://bank.example.evil.example/',
    'https://bank-example.example/',
    'https://bаnk.example/', // Cyrillic а
  ]) {
    assert.notEqual(originOfUrl(url), bank, url);
  }
});
