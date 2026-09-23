/**
 * Recreate the demo account under the NEW native-Argon2 parameters.
 *
 * Why this is needed: the KDF moved from t=2/m=16MB (pure JS) to t=3/m=64MB
 * (native), so every previously derived key is different and the old vault can
 * no longer be decrypted. There is no re-encrypt path in Phase 1.
 *
 * KEY-COMPATIBILITY NOTE — the reason this script can work at all:
 * Argon2id is RFC 9106. @noble/hashes here and react-native-argon2 on the phone
 * must produce identical output for identical inputs, so the two must agree on
 * every parameter INCLUDING how the salt is interpreted. The app passes
 * saltEncoding:'hex', meaning the native side decodes the hex salt to its 16 raw
 * bytes — so this script hex-decodes it too. Passing the hex *string* instead
 * would silently derive a different key and the phone would report "incorrect
 * master password" with nothing obviously wrong.
 */
import 'dotenv/config'
import crypto from 'node:crypto'
import { Buffer } from 'buffer'
import { argon2id } from '../mobile/node_modules/@noble/hashes/argon2.js'
import { xchacha20poly1305 } from '../mobile/node_modules/@noble/ciphers/chacha.js'
import { utf8ToBytes } from '../mobile/node_modules/@noble/ciphers/utils.js'

const BASE = process.env.SEED_API || 'http://127.0.0.1:4000/api'
const EMAIL = 'demo@vault.test'
const LOGIN_PW = 'demo12345'
const MASTER_PW = 'demomaster1234'

// MUST match mobile/src/services/crypto-service.js KDF_PARAMS exactly.
const KDF = { t: 3, m: 65536, p: 1, dkLen: 32 }
const CANARY = 'personal-vault-ok-v1'

const b64 = (x) => Buffer.from(x).toString('base64')
const enc = (o, k) => {
  const n = new Uint8Array(crypto.randomBytes(24))
  return {
    encryptedData: b64(xchacha20poly1305(k, n).encrypt(utf8ToBytes(JSON.stringify(o)))),
    iv: b64(n),
  }
}
const call = async (m, p, o = {}) => {
  const r = await fetch(`${BASE}${p}`, {
    method: m,
    headers: { 'Content-Type': 'application/json', ...(o.auth && { Authorization: `Bearer ${o.auth}` }) },
    ...(o.body && { body: JSON.stringify(o.body) }),
  })
  let j = null
  try { j = await r.json() } catch {}
  return { status: r.status, data: j?.data, error: j?.error }
}

// 1. fresh account (delete any previous one first — its key is unrecoverable)
const mongoose = (await import('mongoose')).default
await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 15000 })
const users = mongoose.connection.db.collection('users')
const existing = await users.findOne({ email: EMAIL })
if (existing) {
  await mongoose.connection.db.collection('vaultitems').deleteMany({ userId: existing._id })
  await users.deleteOne({ _id: existing._id })
  console.log('  removed the old demo account (its key cannot be re-derived)')
}
await mongoose.disconnect()

const s = await call('POST', '/auth/signup', { body: { email: EMAIL, password: LOGIN_PW } })
if (s.status !== 201) { console.log('  signup failed:', s.status, JSON.stringify(s.error)); process.exit(1) }
console.log('  account created:', EMAIL)

const token = s.data.accessToken
const saltHex = s.data.kdfSalt

// 2. derive with the SAME parameters the phone will use
console.log(`  deriving key (t=${KDF.t}, m=${KDF.m / 1024}MB, salt hex-decoded)…`)
const t0 = Date.now()
const key = argon2id(MASTER_PW, Buffer.from(saltHex, 'hex'), KDF)
console.log(`  derived in ${Date.now() - t0}ms on this laptop`)

// 3. canary
const v = enc(CANARY, key)
const init = await call('POST', '/auth/vault/init', {
  auth: token,
  body: { verifierCiphertext: v.encryptedData, verifierIv: v.iv },
})
if (init.status !== 200) { console.log('  vault init failed:', JSON.stringify(init.error)); process.exit(1) }
console.log('  vault initialised')

// 4. sample items
const samples = [
  ['password', { username: 'sahil@gmail.com', password: 'Str0ng!Pass#2026', url: 'https://gmail.com', notes: 'Personal email' }, { title: 'Gmail', folder: 'Personal', favorite: true }],
  ['bank', { bankName: 'HDFC Bank', branch: 'Andheri West', accountType: 'Savings', accountNumber: '50100234567890', ifsc: 'HDFC0001234', netBankingId: 'sahiljr', netBankingPassword: 'NetB@nk2026!', mpin: '4821', customerId: '90218374' }, { title: 'HDFC Savings', folder: 'Personal', favorite: true }],
  ['card', { cardholderName: 'SAHIL JR', cardNumber: '4111 1111 1111 1111', expiry: '08/29', cvv: '852', pin: '4417' }, { title: 'HDFC Regalia', folder: 'Personal', favorite: false }],
  ['note', { body: 'WiFi password: hunter2-not-really\nRouter admin: 192.168.0.1' }, { title: 'Home WiFi', folder: 'Personal', favorite: false }],
]
for (const [category, fields, metadata] of samples) {
  const { encryptedData, iv } = enc(fields, key)
  const r = await call('POST', '/vault/items', { auth: token, body: { category, encryptedData, iv, metadata } })
  console.log(`  ${r.status === 201 ? '✓' : '✗'} ${category.padEnd(9)} ${metadata.title}`)
}

console.log('\n  ─────────────────────────────')
console.log('   Email           :', EMAIL)
console.log('   Login password  :', LOGIN_PW)
console.log('   Master password :', MASTER_PW)
console.log('  ─────────────────────────────')
console.log('\n  If the phone says "incorrect master password", the native and JS')
console.log('  Argon2 disagree on a parameter — check saltEncoding first.')
