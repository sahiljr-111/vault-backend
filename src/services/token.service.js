import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'
import { env } from '../config/env.js'

export function signAccessToken(userId) {
  return jwt.sign({ sub: String(userId), type: 'access' }, env.jwt.accessSecret, {
    expiresIn: env.jwt.accessTtl,
  })
}

export function signRefreshToken(userId) {
  return jwt.sign({ sub: String(userId), type: 'refresh' }, env.jwt.refreshSecret, {
    expiresIn: env.jwt.refreshTtl,
  })
}

export function verifyRefreshToken(token) {
  const payload = jwt.verify(token, env.jwt.refreshSecret)
  if (payload.type !== 'refresh') throw new Error('wrong token type')
  return payload
}

/** Store only a hash of the refresh token, so a DB dump can't be replayed as a session. */
export function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex')
}

export function issueTokens(userId) {
  const accessToken = signAccessToken(userId)
  const refreshToken = signRefreshToken(userId)
  return { accessToken, refreshToken, refreshTokenHash: hashToken(refreshToken) }
}

/**
 * A short-lived ticket proving one thing: this person just proved control of
 * the account's email address.
 *
 * `type: 'reset'` is checked on the way back in, so an access token cannot be
 * substituted for one of these and vice versa — without the discriminator, any
 * valid session token would be accepted as proof of an email challenge that
 * never happened.
 *
 * It authorises re-wrapping the key under a new password. It does NOT decrypt
 * anything: the vault key is recovered on the DEVICE from the recovery code,
 * so email alone still opens nothing (rule 1).
 */
export function signResetToken(userId) {
  return jwt.sign({ sub: String(userId), type: 'reset' }, env.jwt.accessSecret, {
    expiresIn: '15m',
  })
}

export function verifyResetToken(token) {
  const payload = jwt.verify(token, env.jwt.accessSecret)
  if (payload.type !== 'reset') throw new Error('WRONG_TOKEN_TYPE')
  return payload
}
