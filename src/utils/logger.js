import { env } from '../config/env.js'

/**
 * Log SHAPE, never CONTENT (security rule 3).
 *
 * Never pass into these: a master password, a vault key or any prefix of one,
 * a decrypted item, `req.body` on an auth/vault route, or a JWT.
 * Ciphertext is not useful in logs either — log counts and ids instead.
 */
const redactKeys = new Set([
  'password', 'masterPassword', 'newPassword', 'token', 'accessToken', 'refreshToken',
  'encryptedData', 'encryptedBlob', 'iv', 'kdfSalt', 'passwordHash',
  'verifierCiphertext', 'verifierIv', 'authorization',
])

function scrub(meta) {
  if (!meta || typeof meta !== 'object') return meta
  const out = {}
  for (const [k, v] of Object.entries(meta)) {
    if (redactKeys.has(k)) out[k] = '[redacted]'
    else if (v && typeof v === 'object') out[k] = scrub(v)
    else out[k] = v
  }
  return out
}

function emit(level, msg, meta) {
  const line = { level, msg, at: new Date().toISOString(), ...scrub(meta) }
  const fn = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log
  fn(env.isProd ? JSON.stringify(line) : `[${level}] ${msg}`, env.isProd ? '' : (meta ? scrub(meta) : ''))
}

export const logger = {
  info: (msg, meta) => emit('info', msg, meta),
  warn: (msg, meta) => emit('warn', msg, meta),
  error: (msg, meta) => emit('error', msg, meta),
}
