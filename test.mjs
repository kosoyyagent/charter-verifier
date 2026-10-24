import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyAttestation } from './verifier.mjs';

// build a synthetic getAttestation return blob for our schema
const pad = h => h.padStart(64, '0');
function encStr(s) {
  const b = Buffer.from(s, 'utf8');
  return pad(b.length.toString(16)) + b.toString('hex').padEnd(Math.ceil(b.length / 32) * 64, '0');
}
function encStrArray(items) {
  const heads = items.map(() => null);
  let tail = '', offs = [], off = items.length * 32;
  for (const s of items) { offs.push(off); const e = encStr(s); off += e.length / 2; tail += e; }
  return pad(items.length.toString(16)) + offs.map(o => pad(o.toString(16))).join('') + tail;
}
function encBytes32Array(items) {
  return pad(items.length.toString(16)) + items.join('');
}
function buildAttestationData(texts) {
  const names = Object.keys(texts).sort();
  const digests = names.map(n => createHash('sha256').update(texts[n], 'utf8').digest('hex'));
  const cids = names.map((_, i) => `cid${i}`);
  // data tuple: 5 dyn fields
  const parts = [encStr('1.0'), encStr('2026-10-23'), encStrArray(names), encBytes32Array(digests), encStrArray(cids)];
  const headLen = 5 * 32;
  let off = headLen, offs = [], tail = '';
  for (const p of parts) { offs.push(off); off += p.length / 2; tail += p; }
  const dataHex = offs.map(o => pad(o.toString(16))).join('') + tail;
  // wrap: attestation struct head = 11 words, last is offset to data
  const head = [...Array(10)].map((_, i) => pad(i === 9 ? '1' : '0')).join('')
    + pad((11 * 32).toString(16));
  return '0x' + head + dataHex;
}

const texts = { charter: 'Charter v1 text', soul: 'SOUL document' };
const blob = buildAttestationData(texts);

// fake IPFS via global fetch patch
const origFetch = globalThis.fetch;
globalThis.fetch = async (u) => {
  const cid = String(u).split('/').pop();
  const idx = Number(cid.replace('cid', ''));
  const name = Object.keys(texts).sort()[idx];
  return new Response(texts[name]);
};

test('attestation verifies: all texts match', async () => {
  const r = await verifyAttestation({
    uid: '0x' + 'ab'.repeat(32), network: 'base',
    rpc: 'http://fake', fetchJson: async () => ({ result: blob }),
    ipfsGateway: 'http://ipfs/',
  });
  assert.equal(r.allMatch, true);
  assert.equal(r.texts.length, 2);
  assert.ok(r.texts.every(t => t.match));
});

test('tampered text flagged as mismatch', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async (u) => {
    const cid = String(u).split('/').pop();
    const idx = Number(cid.replace('cid', ''));
    const name = Object.keys(texts).sort()[idx];
    return new Response(name === 'charter' ? 'TAMPERED' : texts[name]);
  };
  const r = await verifyAttestation({
    uid: '0x' + 'ab'.repeat(32), rpc: 'http://fake',
    fetchJson: async () => ({ result: blob }), ipfsGateway: 'http://ipfs/',
  });
  globalThis.fetch = orig;
  assert.equal(r.allMatch, false);
  assert.equal(r.texts.find(t => t.name === 'charter').match, false);
  assert.equal(r.texts.find(t => t.name === 'soul').match, true);
});
