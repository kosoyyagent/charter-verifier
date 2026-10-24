// Charter attestation verifier: EAS attestation UID on Base -> read texts from
// IPFS, recompute sha256, show match/mismatch. Static, no backend.
// Runs in browser and Node 20.
import { createHash } from 'node:crypto';

const CHAINS = {
  base:         { chainId: 8453,  eas: '0x4200000000000000000000000000000000000021', rpc: 'https://mainnet.base.org' },
  'base-sepolia': { chainId: 84532, eas: '0x4200000000000000000000000000000000000021', rpc: 'https://sepolia.base.org' },
};
const GET_ATTESTATION_SEL = '0xb838aba1'; // getAttestation(bytes32) -> Attestation tuple

// minimal ABI helpers (dynamic tuple decode for our schema)
const hex = n => n.toString(16).padStart(64, '0');
const strip = h => h.replace(/^0x/, '');

export async function ethCall(rpc, to, data, fetchJson = defaultFetchJson) {
  const r = await fetchJson(rpc, { jsonrpc: '2.0', id: 1, method: 'eth_call',
    params: [{ to, data }, 'latest'] });
  if (r.error) throw new Error(r.error.message);
  return r.result;
}
async function defaultFetchJson(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}

// EAS getAttestation returns a struct; our schema's payload lives in `data`.
// We decode the (string version, string date, string[] names, bytes32[] digests, string[] cids) tail.
function decodeWords(result) {
  const raw = strip(result);
  // word reader over the tuple; find `data` offset field.
  // Attestation fields: uid,schema,time,expirationTime,revocationTime,refUID,recipient,attester,revocable,revocationTime,data(bytes)
  // head = 11 words; data is last -> offset at index 10
  const word = i => raw.slice(i * 64, (i + 1) * 64);
  const dataOff = parseInt(word(10), 16);
  const dyn = raw.slice(dataOff * 2);
  // data = 5 dynamic fields: version, date, names[], digests[], cids[]
  const off = i => parseInt(dyn.slice(i * 64, (i + 1) * 64), 16);
  const str = o => {
    const len = parseInt(dyn.slice(o * 2, o * 2 + 64), 16);
    return Buffer.from(dyn.slice(o * 2 + 64, o * 2 + 64 + len * 2), 'hex').toString('utf8');
  };
  const arrOff = i => { // returns BYTE offsets of each element within dyn
    const base = off(i) * 2;                 // char offset of length word
    const len = parseInt(dyn.slice(base, base + 64), 16);
    const items = [];
    for (let k = 0; k < len; k++) {
      const rel = parseInt(dyn.slice(base + 64 + k * 64, base + 128 + k * 64), 16);
      items.push((base + 64) / 2 + rel);     // head offsets are relative to first head word
    }
    return items;
  };
  const version = str(off(0)), date = str(off(1));
  const names = arrOff(2).map(o => str(o));
  const digestPtrs = (() => {
    const base2 = off(3) * 2;
    const len = parseInt(dyn.slice(base2, base2 + 64), 16);
    return [...Array(len)].map((_, k) => dyn.slice(base2 + 64 + k * 64, base2 + 128 + k * 64));
  })();
  const cids = arrOff(4).map(o => str(o));
  return { version, date, names, digests: digestPtrs, cids };
}

export async function verifyAttestation({ uid, network = 'base', rpc, fetchJson, ipfsGateway = 'https://ipfs.io/ipfs/' }) {
  const chain = CHAINS[network] || CHAINS.base;
  const rpcUrl = rpc || chain.rpc;
  const fj = fetchJson || defaultFetchJson;
  const res = await ethCall(rpcUrl, chain.eas, GET_ATTESTATION_SEL + strip(uid).padStart(64, '0'), fj);
  const decoded = decodeWords(res);
  const hashFn = typeof window !== 'undefined'
    ? async b => { const d = await crypto.subtle.digest('SHA-256', b); return Buffer.from(d).toString('hex'); }
    : async b => createHash('sha256').update(b).digest('hex');
  const texts = [];
  let allMatch = true;
  for (let i = 0; i < decoded.cids.length; i++) {
    const row = { name: decoded.names[i], cid: decoded.cids[i], expected: decoded.digests[i] };
    try {
      const r = await fetch(ipfsGateway + decoded.cids[i]);
      if (!r.ok) throw new Error(`ipfs HTTP ${r.status}`);
      row.sha256 = await hashFn(Buffer.from(await r.arrayBuffer()));
      row.match = row.sha256 === row.expected;
    } catch (e) { row.error = e.message; row.match = false; }
    if (!row.match) allMatch = false;
    texts.push(row);
  }
  return { attestation: decoded, texts, allMatch, uid, network };
}
